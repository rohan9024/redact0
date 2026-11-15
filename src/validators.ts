import type { RuleMatchContext } from './types';

function digitsOnly(input: string): string {
  return input.replace(/\D/g, '');
}

/** ISO/IEC 7812 Luhn Mod-10 check. */
export function isValidLuhn(input: string): boolean {
  const digits = digitsOnly(input);
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/** CMS National Provider Identifier (10 digits; Luhn over "80840" + NPI). */
export function isValidNpi(input: string): boolean {
  const digits = digitsOnly(input);
  if (!/^[12]\d{9}$/.test(digits)) return false;
  const full = '80840' + digits;
  let sum = 0;
  let shouldDouble = false;
  for (let i = full.length - 1; i >= 0; i--) {
    let digit = full.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * US DEA Registration Number (2 letters + 7 digits).
 * Checksum: ((d1 + d3 + d5) + 2 * (d2 + d4 + d6)) % 10 === d7
 */
export function isValidDea(input: string): boolean {
  const clean = input.trim().toUpperCase();
  if (!/^[ABFGMPRX][A-Z9]\d{7}$/.test(clean)) return false;
  const d = (idx: number) => clean.charCodeAt(2 + idx) - 48;
  const oddSum = d(0) + d(2) + d(4);
  const evenSum = d(1) + d(3) + d(5);
  const check = (oddSum + 2 * evenSum) % 10;
  return check === d(6);
}

/**
 * CMS Medicare Beneficiary Identifier (MBI) — 11 chars excluding S, L, O, I, B, Z.
 * Positions: C A AN N A AN N A A N N
 */
const MBI_ALPHA = 'ACDEFGHJKMNPQRTUVWXY';
const MBI_ALNUM = '0123456789' + MBI_ALPHA;

export function isValidMbi(input: string): boolean {
  const clean = input.replace(/-/g, '').toUpperCase();
  if (clean.length !== 11) return false;
  const c0 = clean.charCodeAt(0);
  if (c0 < 49 || c0 > 57) return false; // 1..9
  if (!MBI_ALPHA.includes(clean[1]!)) return false;
  if (!MBI_ALNUM.includes(clean[2]!)) return false;
  if (!/\d/.test(clean[3]!)) return false;
  if (!MBI_ALPHA.includes(clean[4]!)) return false;
  if (!MBI_ALNUM.includes(clean[5]!)) return false;
  if (!/\d/.test(clean[6]!)) return false;
  if (!MBI_ALPHA.includes(clean[7]!)) return false;
  if (!MBI_ALPHA.includes(clean[8]!)) return false;
  if (!/\d\d/.test(clean.slice(9, 11))) return false;
  return true;
}

const IBAN_LENGTHS: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22,
  BR: 29, BY: 28, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28,
  EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23,
  GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26,
  IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20,
  LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18,
  NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24,
  SE: 24, SI: 19, SK: 24, SM: 27, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26,
  UA: 29, VA: 22, VG: 24, XK: 20,
};

/** ISO 13616 IBAN country length + Mod-97 check. */
export function isValidIban(input: string): boolean {
  const clean = input.replace(/[\s-]+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(clean)) return false;
  const expectedLen = IBAN_LENGTHS[clean.slice(0, 2)];
  if (expectedLen !== undefined && clean.length !== expectedLen) return false;

  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      remainder = (remainder * 10 + (code - 48)) % 97;
    } else if (code >= 65 && code <= 90) {
      const val = code - 55; // A=10 .. Z=35
      remainder = (remainder * 100 + val) % 97;
    } else {
      return false;
    }
  }
  return remainder === 1;
}

/** UK NHS 10-digit Number Mod-11 check. */
export function isValidNhs(input: string): boolean {
  const digits = digitsOnly(input);
  if (digits.length !== 10 || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += (digits.charCodeAt(i) - 48) * (10 - i);
  }
  const rem = sum % 11;
  let check = 11 - rem;
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === digits.charCodeAt(9) - 48;
}

/** US SSN structural validation (rejects 000/666/9xx area, 00 group, 0000 serial). */
export function isValidSsn(input: string, ctx?: RuleMatchContext): boolean {
  const clean = input.trim();
  const hasSeparators = /[-\s]/.test(clean);
  const digits = digitsOnly(clean);
  if (digits.length !== 9) return false;

  const area = Number(digits.slice(0, 3));
  const group = Number(digits.slice(3, 5));
  const serial = Number(digits.slice(5, 9));
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0 || serial === 0) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  if (!hasSeparators && ctx) {
    const prefix = ctx.fullText.slice(Math.max(0, ctx.start - 36), ctx.start);
    return /\b(ssn|social[\s_-]?security|tin)\b/i.test(prefix);
  }
  return true;
}

// Verhoeff dihedral D5 tables for 12-digit Indian Aadhaar validation.
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/** 12-digit Indian Aadhaar Verhoeff checksum (starts 2-9). */
export function isValidAadhaar(input: string): boolean {
  const digits = digitsOnly(input);
  if (!/^[2-9]\d{11}$/.test(digits)) return false;
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![digit]!]!;
  }
  return c === 0;
}

/** German 11-digit Steuer-Identifikationsnummer (ISO 7064 Mod 11,10). */
export function isValidDeTaxId(input: string): boolean {
  const digits = digitsOnly(input);
  if (!/^[1-9]\d{10}$/.test(digits)) return false;
  const counts = new Array<number>(10).fill(0);
  for (let i = 0; i < 10; i++) {
    counts[digits.charCodeAt(i) - 48]! += 1;
  }
  const twosOrThrees = counts.filter((c) => c === 2 || c === 3).length;
  const maxFreq = Math.max(...counts);
  if (twosOrThrees !== 1 || maxFreq > 3) return false;

  let product = 10;
  for (let i = 0; i < 10; i++) {
    let sum = (digits.charCodeAt(i) - 48 + product) % 10;
    if (sum === 0) sum = 10;
    product = (sum * 2) % 11;
  }
  let check = 11 - product;
  if (check === 10) check = 0;
  return check === digits.charCodeAt(10) - 48;
}

/** Base64url JWT header sanity check (`{"alg":...}` or `{"typ":...}`). */
export function isValidJwt(input: string): boolean {
  const parts = input.split('.');
  if (parts.length !== 3) return false;
  const headerB64 = parts[0]!;
  if (!headerB64.startsWith('eyJ')) return false;
  try {
    const normalized = headerB64.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (normalized.length % 4)) % 4;
    const decoded = atob(normalized + '='.repeat(padLen));
    return decoded.startsWith('{') && decoded.includes('"');
  } catch {
    return false;
  }
}

export function isPrivateOrLoopbackIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  const [a, b] = parts;
  if (a === undefined || b === undefined) return false;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (p.length === 0 || (p.length > 1 && p.startsWith('0'))) return false;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const freq = new Map<number, number>();
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    freq.set(code, (freq.get(code) ?? 0) + 1);
  }
  let entropy = 0;
  const len = input.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
