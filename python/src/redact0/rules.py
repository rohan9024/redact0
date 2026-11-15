from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Pattern

from .validators import (
    is_valid_aadhaar,
    is_valid_de_tax_id,
    is_valid_dea,
    is_valid_iban,
    is_valid_ipv4,
    is_valid_jwt,
    is_valid_luhn,
    is_valid_mbi,
    is_valid_nhs,
    is_valid_npi,
    is_valid_ssn,
    shannon_entropy,
)

ALL_PRESETS = ("default", "secrets", "hipaa", "gdpr", "strict")
PII_PRESETS = ("default", "hipaa", "gdpr", "strict")
HIPAA_STRICT = ("hipaa", "strict")
GDPR_STRICT = ("gdpr", "strict")


@dataclass(frozen=True)
class DetectorRule:
    id: str
    category: str
    pattern: Pattern[str]
    priority: int
    presets: tuple[str, ...]
    capture_group: int | None = None
    context_regex: Pattern[str] | None = None
    context_window: int = 40
    validate: Callable[[str, str, int], bool] | None = None


def _cc_validate(val: str, _full: str, _start: int) -> bool:
    digits = re.sub(r"\D", "", val)
    return bool(
        re.fullmatch(
            r"(?:4\d{12}(?:\d{3})?(?:\d{3})?|5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01]|720)\d{12}|3[47]\d{13}|6(?:011|5\d\d)\d{12}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11})",
            digits,
        )
    ) and is_valid_luhn(digits)


def _phone_validate(val: str, _full: str, _start: int) -> bool:
    digits = re.sub(r"\D", "", val)
    return 10 <= len(digits) <= 15 and len(set(digits)) > 1


BUILTIN_RULES: tuple[DetectorRule, ...] = (
    DetectorRule(
        id="pem-private-key",
        category="PRIVATE_KEY",
        priority=100,
        presets=ALL_PRESETS,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]{16,8192}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    DetectorRule(
        id="connection-uri-password",
        category="CONNECTION_URI",
        priority=96,
        presets=ALL_PRESETS,
        capture_group=1,
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|clickhouse|cockroachdb)://[^:\s/@]+:([^@\s/]{3,256})@[^\s\"'<>]+",
            re.I,
        ),
    ),
    DetectorRule(
        id="anthropic-key",
        category="API_KEY",
        priority=95,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\bsk-ant-(?:api\d{2}|admin\d{2}|oat\d{2}|[a-z0-9]+)-[A-Za-z0-9_-]{24,}\b"),
    ),
    DetectorRule(
        id="openai-key",
        category="API_KEY",
        priority=95,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{24,}\b|\bsk-[A-Za-z0-9]{16,}T3BlbkFJ[A-Za-z0-9]{16,}\b"),
    ),
    DetectorRule(
        id="github-token",
        category="API_KEY",
        priority=95,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{40,})\b"),
    ),
    DetectorRule(
        id="aws-access-key",
        category="API_KEY",
        priority=94,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b"),
    ),
    DetectorRule(
        id="stripe-secret",
        category="API_KEY",
        priority=94,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\b(?:sk_live|rk_live|whsec)_[A-Za-z0-9]{20,}\b"),
    ),
    DetectorRule(
        id="google-api-key",
        category="API_KEY",
        priority=93,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    DetectorRule(
        id="slack-token",
        category="TOKEN",
        priority=93,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{14,}\b|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    DetectorRule(
        id="discord-webhook",
        category="SECRET",
        priority=92,
        presets=ALL_PRESETS,
        pattern=re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d{16,22}/[A-Za-z0-9_-]{40,}"),
    ),
    DetectorRule(
        id="provider-prefixed-keys",
        category="API_KEY",
        priority=92,
        presets=ALL_PRESETS,
        pattern=re.compile(
            r"\b(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{36,}|xai-[A-Za-z0-9]{36,}|pplx-[A-Za-z0-9]{36,}|sbp_[A-Za-z0-9]{36,}|sb_secret_[A-Za-z0-9_-]{24,}|re_[A-Za-z0-9_]{24,}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"
        ),
    ),
    DetectorRule(
        id="jwt-token",
        category="JWT",
        priority=90,
        presets=ALL_PRESETS,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\b"),
        validate=lambda v, _f, _s: is_valid_jwt(v),
    ),
    DetectorRule(
        id="bearer-auth-header",
        category="TOKEN",
        priority=88,
        presets=ALL_PRESETS,
        capture_group=1,
        pattern=re.compile(
            r"\b(?:Authorization|Proxy-Authorization)\s*[:=]\s*[\"']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{12,})[\"']?",
            re.I,
        ),
    ),
    DetectorRule(
        id="contextual-secret-assignment",
        category="SECRET",
        priority=72,
        presets=ALL_PRESETS,
        capture_group=1,
        pattern=re.compile(
            r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|aws_secret_access_key|password|passwd|pwd|signing[_-]?secret)\b\s*[:=]\s*[\"']?([^\s\"',;}{]{10,128})[\"']?",
            re.I,
        ),
        validate=lambda v, _f, _s: not v.startswith("[") and not v.startswith("<") and shannon_entropy(v) >= 2.8,
    ),
    DetectorRule(
        id="medicare-mbi",
        category="MBI",
        priority=84,
        presets=HIPAA_STRICT,
        pattern=re.compile(r"\b[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]-?\d[AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]-?\d[AC-HJKMNP-RT-Y]{2}\d{2}\b", re.I),
        validate=lambda v, _f, _s: is_valid_mbi(v),
    ),
    DetectorRule(
        id="us-dea",
        category="DEA",
        priority=83,
        presets=HIPAA_STRICT,
        pattern=re.compile(r"\b[ABFGMPRX][A-Z9]\d{7}\b"),
        validate=lambda v, _f, _s: is_valid_dea(v),
    ),
    DetectorRule(
        id="us-npi",
        category="NPI",
        priority=80,
        presets=HIPAA_STRICT,
        context_regex=re.compile(r"\b(?:npi|provider|prescriber|practitioner|physician)\b", re.I),
        pattern=re.compile(r"\b[12]\d{9}\b"),
        validate=lambda v, _f, _s: is_valid_npi(v),
    ),
    DetectorRule(
        id="uk-nhs-number",
        category="NHS",
        priority=80,
        presets=("hipaa", "gdpr", "strict"),
        context_regex=re.compile(r"\b(?:nhs|patient|health|care|medical)\b", re.I),
        pattern=re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b"),
        validate=lambda v, _f, _s: is_valid_nhs(v),
    ),
    DetectorRule(
        id="medical-record-number",
        category="MRN",
        priority=78,
        presets=HIPAA_STRICT,
        capture_group=1,
        pattern=re.compile(r"\b(?:mrn|medical[\s_-]?record(?:[\s_-]?number)?|patient[\s_-]?id)\s*[:=#]?\s*([A-Z0-9-]{5,20})\b", re.I),
    ),
    DetectorRule(
        id="iban",
        category="IBAN",
        priority=84,
        presets=PII_PRESETS,
        pattern=re.compile(r"\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){11,30}\b"),
        validate=lambda v, _f, _s: is_valid_iban(v),
    ),
    DetectorRule(
        id="credit-card",
        category="CREDIT_CARD",
        priority=82,
        presets=PII_PRESETS,
        pattern=re.compile(r"\b(?:\d[ -]?){13,18}\d\b"),
        validate=_cc_validate,
    ),
    DetectorRule(
        id="us-ssn",
        category="SSN",
        priority=81,
        presets=PII_PRESETS,
        pattern=re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b|\b\d{9}\b"),
        validate=is_valid_ssn,
    ),
    DetectorRule(
        id="aadhaar-in",
        category="AADHAAR",
        priority=76,
        presets=("gdpr", "strict"),
        context_regex=re.compile(r"\b(?:aadhaar|aadhar|uidai)\b", re.I),
        pattern=re.compile(r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b"),
        validate=lambda v, _f, _s: is_valid_aadhaar(v),
    ),
    DetectorRule(
        id="de-tax-id",
        category="TAX_ID",
        priority=76,
        presets=GDPR_STRICT,
        context_regex=re.compile(r"\b(?:steuer|tax|tin|idnr|identifikationsnummer)\b", re.I),
        pattern=re.compile(r"\b[1-9]\d{10}\b"),
        validate=lambda v, _f, _s: is_valid_de_tax_id(v),
    ),
    DetectorRule(
        id="email",
        category="EMAIL",
        priority=75,
        presets=PII_PRESETS,
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b"),
    ),
    DetectorRule(
        id="phone",
        category="PHONE",
        priority=65,
        presets=PII_PRESETS,
        pattern=re.compile(r"(?:\+\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)[-.\s]?|\b\d{3}[-.\s])\d{3,4}[-.\s]\d{4}\b|\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
        validate=_phone_validate,
    ),
    DetectorRule(
        id="ipv4",
        category="IP_ADDRESS",
        priority=60,
        presets=PII_PRESETS,
        pattern=re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        validate=lambda v, _f, _s: is_valid_ipv4(v),
    ),
    DetectorRule(
        id="mac-address",
        category="MAC_ADDRESS",
        priority=58,
        presets=("hipaa", "gdpr", "strict"),
        pattern=re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    ),
    DetectorRule(
        id="labeled-person-name",
        category="PERSON",
        priority=55,
        presets=HIPAA_STRICT,
        capture_group=1,
        pattern=re.compile(
            r"\b(?:Patient(?:\s+Name)?|Dr\.|Doctor|Clinician|Provider|Mr\.|Mrs\.|Ms\.|Full\s+Name|Beneficiary)\s*[:.]?\s*([A-Z][a-z]{1,24}(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]{1,24}){1,2})"
        ),
    ),
    DetectorRule(
        id="dob-or-clinical-date",
        category="DATE",
        priority=52,
        presets=HIPAA_STRICT,
        context_regex=re.compile(r"\b(?:dob|birth|born|admit(?:ted)?|discharg(?:e|ed)|visit|encounter|date)\b", re.I),
        pattern=re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2})\b"),
    ),
)
