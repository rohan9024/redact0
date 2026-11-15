from __future__ import annotations

import base64
import math
import re
from collections import Counter

_IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22,
    "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18,
    "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26,
    "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

_MBI_ALPHA = set("ACDEFGHJKMNPQRTUVWXY")
_MBI_ALNUM = _MBI_ALPHA | set("0123456789")

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _digits_only(val: str) -> str:
    return re.sub(r"\D", "", val)


def is_valid_luhn(val: str) -> bool:
    digits = _digits_only(val)
    if not (13 <= len(digits) <= 19) or len(set(digits)) == 1:
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def is_valid_npi(val: str) -> bool:
    digits = _digits_only(val)
    if not re.fullmatch(r"[12]\d{9}", digits):
        return False
    full = "80840" + digits
    total = 0
    double = False
    for ch in reversed(full):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def is_valid_dea(val: str) -> bool:
    clean = val.strip().upper()
    if not re.fullmatch(r"[ABFGMPRX][A-Z9]\d{7}", clean):
        return False
    d = [ord(c) - 48 for c in clean[2:]]
    return ((d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]


def is_valid_mbi(val: str) -> bool:
    c = val.replace("-", "").upper()
    if len(c) != 11:
        return False
    return (
        "1" <= c[0] <= "9"
        and c[1] in _MBI_ALPHA
        and c[2] in _MBI_ALNUM
        and c[3].isdigit()
        and c[4] in _MBI_ALPHA
        and c[5] in _MBI_ALNUM
        and c[6].isdigit()
        and c[7] in _MBI_ALPHA
        and c[8] in _MBI_ALPHA
        and c[9:11].isdigit()
    )


def is_valid_iban(val: str) -> bool:
    clean = re.sub(r"[\s-]+", "", val).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", clean):
        return False
    expected = _IBAN_LENGTHS.get(clean[:2])
    if expected is not None and len(clean) != expected:
        return False
    rearranged = clean[4:] + clean[:4]
    rem = 0
    for ch in rearranged:
        if "0" <= ch <= "9":
            rem = (rem * 10 + (ord(ch) - 48)) % 97
        elif "A" <= ch <= "Z":
            rem = (rem * 100 + (ord(ch) - 55)) % 97
        else:
            return False
    return rem == 1


def is_valid_nhs(val: str) -> bool:
    digits = _digits_only(val)
    if len(digits) != 10 or len(set(digits)) == 1:
        return False
    total = sum((ord(digits[i]) - 48) * (10 - i) for i in range(9))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == (ord(digits[9]) - 48)


def is_valid_ssn(val: str, full_text: str = "", start: int = 0) -> bool:
    clean = val.strip()
    has_sep = bool(re.search(r"[-\s]", clean))
    digits = _digits_only(clean)
    if len(digits) != 9 or len(set(digits)) == 1:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area in (0, 666) or area >= 900 or group == 0 or serial == 0:
        return False
    if not has_sep and full_text:
        prefix = full_text[max(0, start - 36) : start]
        return bool(re.search(r"\b(ssn|social[\s_-]?security|tin)\b", prefix, re.I))
    return True


def is_valid_aadhaar(val: str) -> bool:
    digits = _digits_only(val)
    if not re.fullmatch(r"[2-9]\d{11}", digits):
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][ord(ch) - 48]]
    return c == 0


def is_valid_de_tax_id(val: str) -> bool:
    digits = _digits_only(val)
    if not re.fullmatch(r"[1-9]\d{10}", digits):
        return False
    counts = Counter(digits[:10])
    if sum(1 for v in counts.values() if v in (2, 3)) != 1 or max(counts.values()) > 3:
        return False
    product = 10
    for ch in digits[:10]:
        s = (ord(ch) - 48 + product) % 10
        if s == 0:
            s = 10
        product = (s * 2) % 11
    check = 11 - product
    if check == 10:
        check = 0
    return check == (ord(digits[10]) - 48)


def is_valid_jwt(val: str) -> bool:
    parts = val.split(".")
    if len(parts) != 3 or not parts[0].startswith("eyJ"):
        return False
    try:
        padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        return decoded.startswith("{") and '"' in decoded
    except Exception:
        return False


def is_valid_ipv4(val: str) -> bool:
    parts = val.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p or (len(p) > 1 and p.startswith("0")) or not p.isdigit():
            return False
        if not (0 <= int(p) <= 255):
            return False
    return True


def is_private_or_loopback_ipv4(val: str) -> bool:
    parts = [int(x) for x in val.split(".")]
    a, b = parts[0], parts[1]
    return a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254)


def shannon_entropy(val: str) -> float:
    if not val:
        return 0.0
    counts = Counter(val)
    length = len(val)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
