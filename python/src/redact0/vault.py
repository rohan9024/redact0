from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .rules import BUILTIN_RULES, DetectorRule
from .validators import is_private_or_loopback_ipv4

_RESERVED_TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+(?:#[a-f0-9]{4,8})?\]|<[A-Z_]+_\d+(?:#[a-f0-9]{4,8})?>")
_SENSITIVE_KEY_RE = re.compile(
    r"^(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|authorization|cookie|set-cookie|x-api-key|client[_-]?secret|private[_-]?key|ssn|social[_-]?security(?:[_-]?number)?|cvv|cvc|pin|iban|dob|birth[_-]?date|mrn)$",
    re.I,
)

RESTRICTED_ZIP3_CONSERVATIVE = frozenset(
    {
        "036", "059", "063", "102", "203", "205", "369", "556", "692",
        "790", "821", "823", "830", "831", "878", "879", "884", "890", "893",
    }
)


@dataclass(frozen=True)
class Finding:
    id: str
    category: str
    start: int
    end: int
    token: str
    length: int
    fingerprint: str


@dataclass(frozen=True)
class RedactResult:
    value: Any
    findings: list[Finding]

    @property
    def count(self) -> int:
        return len(self.findings)


def _hmac_hex(key: str, msg: str, length: int = 12) -> str:
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()[:length]


class Vault:
    def __init__(
        self,
        preset: str = "default",
        *,
        categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        rules: list[DetectorRule] | None = None,
        literals: list[str] | None = None,
        allowlist: list[str] | None = None,
        secret: str | None = None,
        token_format: str = "bracket",
        redact_private_ips: bool | None = None,
        mask_char: str = "*",
    ) -> None:
        self.preset = preset
        self.literals = literals or []
        self.allowlist = set(allowlist or [])
        self._key = secret or secrets.token_hex(16)
        self.token_format = token_format
        self.mask_char = mask_char
        self.redact_private_ips = (
            redact_private_ips if redact_private_ips is not None else preset in ("strict", "hipaa")
        )

        active = list(rules) if rules is not None else [r for r in BUILTIN_RULES if preset in r.presets]
        if categories:
            allowed = set(categories)
            active = [r for r in active if r.category in allowed]
        if exclude_categories:
            blocked = set(exclude_categories)
            active = [r for r in active if r.category not in blocked]
        self._rules = active

        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, tuple[str, str]] = {}
        self._counters: dict[str, int] = {}
        self._reserved: set[str] = set()
        self.version = 0

    def _reserve_existing(self, text: str) -> None:
        for m in _RESERVED_TOKEN_RE.finditer(text):
            tok = m.group(0)
            if tok not in self._reverse:
                self._reserved.add(tok)

    def tokenize(self, category: str, value: str) -> str:
        key = (category, value)
        if key in self._forward:
            return self._forward[key]
        if self.token_format == "mask":
            return self.mask_char * min(max(len(value), 4), 16)
        if self.token_format == "hash":
            tok = f"[{category}:{_hmac_hex(self._key, f'{category}:{value}', 8)}]"
            self._forward[key] = tok
            self._reverse[tok] = key
            self.version += 1
            return tok

        idx = self._counters.get(category, 0)
        while True:
            idx += 1
            if self.token_format == "angle":
                tok = f"<{category}_{idx}>"
            elif self.token_format == "signed":
                tok = f"[{category}_{idx}#{_hmac_hex(self._key, f'{category}:{idx}:{value}', 4)}]"
            else:
                tok = f"[{category}_{idx}]"
            if tok not in self._reserved and tok not in self._reverse:
                break

        self._counters[category] = idx
        self._forward[key] = tok
        self._reverse[tok] = key
        self.version += 1
        return tok

    def _collect(self, text: str) -> list[tuple[str, str, int, int, int, str]]:
        candidates: list[tuple[str, str, int, int, int, str]] = []
        for lit in self.literals:
            if len(lit) < 4:
                continue
            idx = 0
            while True:
                found = text.find(lit, idx)
                if found == -1:
                    break
                candidates.append(("literal-secret", "SECRET", 99, found, found + len(lit), lit))
                idx = found + len(lit)

        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                if rule.capture_group is not None and m.group(rule.capture_group) is not None:
                    val = m.group(rule.capture_group)
                    start = m.start(rule.capture_group)
                    end = m.end(rule.capture_group)
                else:
                    val = m.group(0)
                    start = m.start()
                    end = m.end()
                if not val or val in self.allowlist:
                    continue
                if rule.id == "ipv4" and not self.redact_private_ips and is_private_or_loopback_ipv4(val):
                    continue
                if rule.context_regex is not None:
                    left = text[max(0, start - rule.context_window) : start]
                    right = text[end : min(len(text), end + rule.context_window)]
                    if not (rule.context_regex.search(left) or rule.context_regex.search(right)):
                        continue
                if rule.validate is not None and not rule.validate(val, text, start):
                    continue
                candidates.append((rule.id, rule.category, rule.priority, start, end, val))

        candidates.sort(key=lambda x: (-x[2], -(x[4] - x[3]), x[3]))
        accepted: list[tuple[str, str, int, int, int, str]] = []
        for cand in candidates:
            if not any(cand[3] < a[4] and cand[4] > a[3] for a in accepted):
                accepted.append(cand)
        accepted.sort(key=lambda x: x[3])
        return accepted

    def scan(self, text: str) -> list[Finding]:
        if not text:
            return []
        return [
            Finding(
                id=rid,
                category=cat,
                start=s,
                end=e,
                token=f"[{cat}]",
                length=len(val),
                fingerprint=hashlib.sha256(val.encode("utf-8")).hexdigest()[:12],
            )
            for rid, cat, _prio, s, e, val in self._collect(text)
        ]

    def redact_text(self, text: str) -> RedactResult:
        if not text:
            return RedactResult(value=text, findings=[])
        self._reserve_existing(text)
        matches = self._collect(text)
        if not matches:
            return RedactResult(value=text, findings=[])
        parts: list[str] = []
        findings: list[Finding] = []
        cursor = 0
        for rid, cat, _prio, s, e, val in matches:
            parts.append(text[cursor:s])
            tok = self.tokenize(cat, val)
            parts.append(tok)
            cursor = e
            findings.append(
                Finding(
                    id=rid,
                    category=cat,
                    start=s,
                    end=e,
                    token=tok,
                    length=len(val),
                    fingerprint=_hmac_hex(self._key, val, 12),
                )
            )
        parts.append(text[cursor:])
        return RedactResult(value="".join(parts), findings=findings)

    def redact(self, data: Any) -> RedactResult:
        if isinstance(data, str):
            return self.redact_text(data)
        findings: list[Finding] = []
        seen: dict[int, Any] = {}

        def walk(node: Any, key_hint: str | None = None, depth: int = 0) -> Any:
            if node is None or isinstance(node, (bool, int, float)):
                return node
            if isinstance(node, str):
                if key_hint and _SENSITIVE_KEY_RE.match(key_hint) and node and node not in self._reverse:
                    tok = self.tokenize("SECRET", node)
                    findings.append(
                        Finding(
                            id="sensitive-key",
                            category="SECRET",
                            start=0,
                            end=len(node),
                            token=tok,
                            length=len(node),
                            fingerprint=_hmac_hex(self._key, node, 12),
                        )
                    )
                    return tok
                res = self.redact_text(node)
                findings.extend(res.findings)
                return res.value
            if depth >= 32:
                return "[MAX_DEPTH_TRUNCATED]"
            obj_id = id(node)
            if obj_id in seen:
                return seen[obj_id]
            if isinstance(node, list):
                arr: list[Any] = []
                seen[obj_id] = arr
                for item in node:
                    arr.append(walk(item, key_hint, depth + 1))
                return arr
            if isinstance(node, tuple):
                return tuple(walk(item, key_hint, depth + 1) for item in node)
            if isinstance(node, dict):
                out: dict[Any, Any] = {}
                seen[obj_id] = out
                for k, v in node.items():
                    out[k] = walk(v, str(k) if isinstance(k, str) else None, depth + 1)
                return out
            if isinstance(node, BaseException):
                return self.redact_text(str(node)).value
            return node

        return RedactResult(value=walk(data), findings=findings)

    def restore(self, text: str) -> str:
        if not text or not self._reverse:
            return text
        tokens = sorted(self._reverse.keys(), key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(t) for t in tokens))
        return pattern.sub(lambda m: self._reverse[m.group(0)][1], text)

    def restore_object(self, data: Any) -> Any:
        if isinstance(data, str):
            return self.restore(data)
        if isinstance(data, list):
            return [self.restore_object(x) for x in data]
        if isinstance(data, dict):
            return {k: self.restore_object(v) for k, v in data.items()}
        return data

    def entries(self) -> list[tuple[str, str, str]]:
        return [(tok, meta[0], meta[1]) for tok, meta in self._reverse.items()]


class StreamRestorer:
    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self._cached_version = -1
        self._token_map: dict[str, str] = {}
        self._prefixes: set[str] = set()
        self._first_chars: set[str] = set()
        self._max_len = 0
        self._pending = ""

    def _rebuild(self) -> None:
        if self.vault.version == self._cached_version:
            return
        self._cached_version = self.vault.version
        self._token_map.clear()
        self._prefixes.clear()
        self._first_chars.clear()
        self._max_len = 0
        for tok, _cat, val in self.vault.entries():
            self._token_map[tok] = val
            self._first_chars.add(tok[0])
            self._max_len = max(self._max_len, len(tok))
            for i in range(1, len(tok)):
                self._prefixes.add(tok[:i])

    def _process(self, is_flush: bool) -> str:
        self._rebuild()
        if not self._pending:
            return ""
        if not self._token_map:
            out, self._pending = self._pending, ""
            return out
        out: list[str] = []
        pos = 0
        n = len(self._pending)
        while pos < n:
            ch = self._pending[pos]
            if ch not in self._first_chars:
                out.append(ch)
                pos += 1
                continue
            rem = self._pending[pos:]
            if not is_flush and len(rem) < self._max_len and rem in self._prefixes:
                break
            matched: str | None = None
            for length in range(min(self._max_len, len(rem)), 0, -1):
                candidate = rem[:length]
                if candidate in self._token_map:
                    matched = candidate
                    break
            if matched is not None:
                out.append(self._token_map[matched])
                pos += len(matched)
            else:
                out.append(ch)
                pos += 1
        self._pending = self._pending[pos:]
        return "".join(out)

    def push(self, chunk: str) -> str:
        if not chunk:
            return ""
        self._pending += chunk
        return self._process(False)

    def flush(self) -> str:
        return self._process(True)

    def iter_restore(self, chunks: Iterator[str]) -> Iterator[str]:
        for ch in chunks:
            out = self.push(ch)
            if out:
                yield out
        tail = self.flush()
        if tail:
            yield tail


def create_vault(preset: str = "default", **kwargs: Any) -> Vault:
    return Vault(preset=preset, **kwargs)


def redact(data: Any, preset: str = "default", **kwargs: Any) -> Any:
    return Vault(preset=preset, **kwargs).redact(data).value


def redact_detailed(data: Any, preset: str = "default", **kwargs: Any) -> RedactResult:
    return Vault(preset=preset, **kwargs).redact(data)


def scan(text: str, preset: str = "default", **kwargs: Any) -> list[Finding]:
    return Vault(preset=preset, **kwargs).scan(text)


def redact_fhir(
    resource: dict[str, Any],
    *,
    vault: Vault | None = None,
    date_shift_days: int | None = None,
    cap_age_over_89: bool = True,
) -> tuple[dict[str, Any], Vault]:
    v = vault or Vault(preset="hipaa")
    seed = str(resource.get("id", "default"))
    if date_shift_days is None:
        h = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
        mag = 30 + (h % 151)
        shift_days = mag if h % 2 == 0 else -mag
    else:
        shift_days = date_shift_days

    clinical_keys = {"resourceType", "coding", "code", "system", "unit", "valueQuantity", "gender", "status"}
    cur_year = datetime.now(timezone.utc).year

    def shift_date(val: str, is_birth: bool = False) -> str:
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(.*)$", val)
        if is_birth and cap_age_over_89 and m and (cur_year - int(m.group(1)) > 89):
            return "90+"
        if not m:
            return val
        dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc) + timedelta(days=shift_days)
        return dt.strftime("%Y-%m-%d") + m.group(4)

    def walk(node: Any, path: tuple[str, ...], preserve: bool) -> Any:
        cur = path[-1] if path else ""
        if isinstance(node, str):
            if preserve and cur != "display":
                return node
            if cur == "postalCode":
                digits = re.sub(r"\D", "", node)
                z3 = digits[:3] if len(digits) >= 3 else "000"
                return "000" if z3 in RESTRICTED_ZIP3_CONSERVATIVE else z3
            if cur == "birthDate":
                return shift_date(node, is_birth=True)
            if cur in ("date", "effectiveDateTime", "authoredOn", "onsetDateTime", "recordedDate", "issued"):
                return shift_date(node, is_birth=False)
            if cur in ("family", "given", "prefix", "suffix"):
                return v.tokenize("PERSON", node)
            if cur in ("line", "city"):
                return v.tokenize("ADDRESS", node)
            if cur == "id" or ("identifier" in path and cur == "value"):
                return v.tokenize("MRN", node)
            return v.redact_text(node).value
        if isinstance(node, list):
            return [walk(x, path, preserve) for x in node]
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for k, val in node.items():
                if k == "resourceType":
                    out[k] = val
                elif k == "photo":
                    out[k] = []
                else:
                    out[k] = walk(val, (*path, k), preserve or (k in clinical_keys))
            return out
        return node

    return walk(resource, (), False), v
