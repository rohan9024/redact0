import { sha256Hex } from './crypto';
import { Vault } from './engine';
import type { FhirRedactOptions, RedactResult } from './types';

/**
 * 17 restricted 3-digit US ZIP prefixes under 20,000 population from HHS 45 CFR 164.514(b)(2)(i)(B)
 * (2000 Census baseline).
 */
export const RESTRICTED_ZIP3_HHS_2000 = new Set([
  '036', '059', '063', '102', '203', '556', '692', '790', '821',
  '823', '830', '831', '878', '879', '884', '890', '893',
]);

/**
 * Conservative union of HHS 2000 + 2010 Census under-20k 3-digit ZIP prefixes (adds 205 & 369).
 */
export const RESTRICTED_ZIP3_CONSERVATIVE = new Set([
  ...RESTRICTED_ZIP3_HHS_2000,
  '205',
  '369',
]);

const CLINICAL_PRESERVE_KEYS = new Set([
  'resourceType', 'coding', 'code', 'system', 'display', 'unit',
  'valueQuantity', 'valueCodeableConcept', 'severity', 'clinicalStatus',
  'verificationStatus', 'category', 'gender', 'status', 'intent', 'priority',
]);

const PHI_NAME_KEYS = new Set(['name', 'family', 'given', 'prefix', 'suffix', 'maiden']);
const PHI_TEXT_KEYS = new Set(['text', 'line', 'city', 'district', 'use', 'note', 'description', 'title']);
const STRIP_BIOMETRIC_KEYS = new Set(['photo', 'data']);

const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})(.*)$/;
const YEAR_ONLY_RE = /^\d{4}$/;

function deriveShiftDays(vault: Vault, seedHint?: string): number {
  const seed = seedHint ?? String(vault.export().entries.length) + 'fhir';
  const hex = sha256Hex(seed, 8);
  const num = parseInt(hex, 16);
  // Deterministic non-zero shift in [-180, -30] U [30, 180]
  const mag = 30 + (num % 151);
  return num % 2 === 0 ? mag : -mag;
}

function shiftIsoDate(iso: string, shiftDays: number): string {
  const m = ISO_DATE_RE.exec(iso);
  if (!m) return iso;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const suffix = m[4] ?? '';
  const dt = new Date(Date.UTC(year, month - 1, day));
  if (Number.isNaN(dt.getTime())) return iso;
  dt.setUTCDate(dt.getUTCDate() + shiftDays);
  const y = dt.getUTCFullYear().toString().padStart(4, '0');
  const mo = (dt.getUTCMonth() + 1).toString().padStart(2, '0');
  const da = dt.getUTCDate().toString().padStart(2, '0');
  return `${y}-${mo}-${da}${suffix}`;
}

function isAgeOver89(birthDateStr: string): boolean {
  const m = /^(\d{4})/.exec(birthDateStr);
  if (!m) return false;
  const birthYear = Number(m[1]);
  const currentYear = new Date().getUTCFullYear();
  return currentYear - birthYear > 89;
}

function safeHarborZip(zip: string, baseline: 'hhs-2000' | 'conservative-union'): string {
  const digits = zip.replace(/\D/g, '');
  if (digits.length < 3) return '000';
  const prefix3 = digits.slice(0, 3);
  const restricted = baseline === 'hhs-2000' ? RESTRICTED_ZIP3_HHS_2000 : RESTRICTED_ZIP3_CONSERVATIVE;
  return restricted.has(prefix3) ? '000' : prefix3;
}

/**
 * Scrubs a FHIR R4/R5 resource or Bundle in accordance with HIPAA Safe Harbor
 * (45 CFR §164.514(b)) while preserving clinical codes and numerical observations.
 */
export function redactFHIR<T extends Record<string, unknown>>(
  resource: T,
  options: FhirRedactOptions = {},
  existingVault?: Vault
): RedactResult<T> & { vault: Vault } {
  const vault = existingVault ?? new Vault({ ...options, preset: options.preset ?? 'hipaa' });
  const zipBaseline = options.zipBaseline ?? 'conservative-union';
  const dateStrategy = options.dateStrategy ?? 'shift';
  const capAge = options.capAgeOver89 ?? true;
  const preserveClinical = options.preserveClinicalCodes ?? true;

  const patientSeed =
    typeof resource.id === 'string'
      ? resource.id
      : JSON.stringify((resource as { identifier?: unknown }).identifier ?? 'default');
  const shiftDays = options.dateShiftDays ?? deriveShiftDays(vault, patientSeed);

  const transformDate = (val: string, isBirthDate: boolean): string => {
    if (isBirthDate && capAge && isAgeOver89(val)) {
      return '90+';
    }
    if (YEAR_ONLY_RE.test(val)) return val;
    if (dateStrategy === 'redact') {
      return vault.tokenize('DATE', val);
    }
    if (dateStrategy === 'year-only') {
      const ym = /^(\d{4})/.exec(val);
      return ym ? ym[1]! : vault.tokenize('DATE', val);
    }
    return shiftIsoDate(val, shiftDays);
  };

  const walk = (node: unknown, keyPath: string[], insideClinicalPreserve: boolean): unknown => {
    if (node === null || node === undefined) return node;

    const currentKey = keyPath[keyPath.length - 1] ?? '';

    if (typeof node === 'string') {
      if (insideClinicalPreserve && currentKey !== 'display') {
        return node;
      }

      if (currentKey === 'postalCode') {
        return safeHarborZip(node, zipBaseline);
      }

      if (currentKey === 'birthDate') {
        return transformDate(node, true);
      }

      if (
        currentKey === 'date' ||
        currentKey === 'effectiveDateTime' ||
        currentKey === 'authoredOn' ||
        currentKey === 'onsetDateTime' ||
        currentKey === 'recordedDate' ||
        currentKey === 'issued' ||
        currentKey === 'start' ||
        currentKey === 'end'
      ) {
        return transformDate(node, false);
      }

      if (currentKey === 'div') {
        // Narrative XHTML block: scrub free-text PII while keeping HTML tags readable
        const scrubbed = vault.redactText(node).value;
        return scrubbed;
      }

      if (PHI_NAME_KEYS.has(currentKey)) {
        return vault.tokenize('PERSON', node);
      }

      if (currentKey === 'line' || currentKey === 'street') {
        return vault.tokenize('ADDRESS', node);
      }

      if (currentKey === 'city') {
        return vault.tokenize('ADDRESS', node);
      }

      if (currentKey === 'id' || (keyPath.includes('identifier') && currentKey === 'value')) {
        return vault.tokenize('MRN', node);
      }

      if (keyPath.includes('telecom') && currentKey === 'value') {
        const res = vault.redactText(node);
        return res.count > 0 ? res.value : vault.tokenize('CUSTOM', node);
      }

      return vault.redactText(node).value;
    }

    if (typeof node !== 'object') return node;

    if (Array.isArray(node)) {
      return node.map((item) => walk(item, keyPath, insideClinicalPreserve));
    }

    const obj = node as Record<string, unknown>;
    const out: Record<string, unknown> = {};

    for (const [k, v] of Object.entries(obj)) {
      if (k === 'resourceType') {
        out[k] = v;
        continue;
      }
      if (STRIP_BIOMETRIC_KEYS.has(k) && (keyPath.includes('photo') || k === 'photo')) {
        out[k] = k === 'photo' ? [] : '[REDACTED_BIOMETRIC]';
        continue;
      }
      if (k === 'name' && (obj.resourceType === 'Patient' || obj.resourceType === 'Practitioner' || obj.resourceType === 'RelatedPerson')) {
        out[k] = walk(v, [...keyPath, k], false);
        continue;
      }
      const nextPreserve = preserveClinical && (insideClinicalPreserve || CLINICAL_PRESERVE_KEYS.has(k));
      if (PHI_TEXT_KEYS.has(k) && !insideClinicalPreserve) {
        out[k] = walk(v, [...keyPath, k], false);
      } else {
        out[k] = walk(v, [...keyPath, k], nextPreserve);
      }
    }
    return out;
  };

  const scrubbed = walk(resource, [], false) as T;
  // Run vault scan summary without mutating already-tokenized fields
  const findings = vault.entries().map((e, i) => ({
    id: 'fhir-phi',
    category: e.category,
    start: i,
    end: i,
    token: e.token,
    length: e.value.length,
    fingerprint: sha256Hex(e.value, 12),
  }));

  return {
    value: scrubbed,
    findings,
    count: findings.length,
    vault,
  };
}
