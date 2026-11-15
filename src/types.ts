export type EntityCategory =
  | 'API_KEY'
  | 'SECRET'
  | 'TOKEN'
  | 'JWT'
  | 'PRIVATE_KEY'
  | 'CONNECTION_URI'
  | 'EMAIL'
  | 'PHONE'
  | 'CREDIT_CARD'
  | 'IBAN'
  | 'SSN'
  | 'NPI'
  | 'DEA'
  | 'MBI'
  | 'NHS'
  | 'MRN'
  | 'AADHAAR'
  | 'TAX_ID'
  | 'IP_ADDRESS'
  | 'MAC_ADDRESS'
  | 'DATE'
  | 'AGE'
  | 'ZIP'
  | 'ADDRESS'
  | 'PERSON'
  | 'CUSTOM';

export type PolicyPreset = 'default' | 'secrets' | 'hipaa' | 'gdpr' | 'strict';

export type TokenFormat = 'bracket' | 'angle' | 'signed' | 'mask' | 'hash';

export interface RuleMatchContext {
  fullText: string;
  match: RegExpExecArray;
  start: number;
  end: number;
  value: string;
}

export interface DetectorRule {
  id: string;
  category: EntityCategory;
  pattern: RegExp;
  /** Capture group index to redact instead of the full match (e.g. URI password). */
  captureGroup?: number;
  /** Higher priority wins when spans overlap. Range 1..100. */
  priority: number;
  /** Presets in which this rule is active. */
  presets: readonly PolicyPreset[];
  /** Optional structural/checksum verifier; must return true to accept match. */
  validate?: (value: string, ctx: RuleMatchContext) => boolean;
  /** Optional context gate evaluated against surrounding characters. */
  contextRegex?: RegExp;
  /** Lookbehind chars inspected for contextRegex (default 40). */
  contextWindow?: number;
}

export interface Finding {
  id: string;
  category: EntityCategory;
  start: number;
  end: number;
  /** Redacted replacement token emitted into output. */
  token: string;
  /** Length of original value (never exposes raw secret in findings/audit). */
  length: number;
  /** Deterministic truncated SHA-256 fingerprint of raw value for audit trails. */
  fingerprint: string;
}

export interface CustomRuleInput {
  id: string;
  category?: EntityCategory;
  pattern: RegExp;
  captureGroup?: number;
  priority?: number;
  validate?: (value: string, ctx: RuleMatchContext) => boolean;
}

export interface RedactOptions {
  preset?: PolicyPreset;
  categories?: readonly EntityCategory[];
  excludeCategories?: readonly EntityCategory[];
  rules?: readonly DetectorRule[];
  customRules?: readonly CustomRuleInput[];
  /** Exact literal strings (e.g. loaded from .env) to always redact. */
  literals?: readonly string[];
  /** JSON keys whose string values should always be redacted. */
  sensitiveKeys?: readonly string[];
  /** Substrings or normalized values never to redact. */
  allowlist?: readonly string[];
  /** Keyed secret used for HMAC fingerprints and signed tokens. */
  secret?: string;
  /** Placeholder format: [EMAIL_1], <EMAIL_1>, [EMAIL_1#a1b2], ***, or [EMAIL:a1b2c3d4]. */
  tokenFormat?: TokenFormat;
  /** Redact private/loopback IPv4 ranges like 127.0.0.1 / 10.x / 192.168.x (default false unless strict/hipaa). */
  redactPrivateIps?: boolean;
  /** Maximum recursion depth for object/JSON walking (default 32). */
  maxDepth?: number;
  /** Redact string keys inside Error stack traces and messages (default true). */
  redactErrors?: boolean;
  /** Fixed replacement string when tokenFormat === 'mask'. */
  maskChar?: string;
}

export interface RedactResult<T = string> {
  value: T;
  findings: Finding[];
  count: number;
}

export interface VaultSnapshot {
  version: 1;
  tokenFormat: TokenFormat;
  counters: Record<string, number>;
  entries: Array<{ token: string; category: EntityCategory; value: string }>;
}

export interface StreamRestorer {
  push(chunk: string): string;
  flush(): string;
  restoreIterable(source: AsyncIterable<string>): AsyncIterable<string>;
  createTransformStream(): TransformStream<string, string>;
}

export interface FhirRedactOptions extends RedactOptions {
  /** 'hhs-2000' (17 ZIP3 prefixes) or 'conservative-union' (19 prefixes incl. 205 & 369). Default 'conservative-union'. */
  zipBaseline?: 'hhs-2000' | 'conservative-union';
  /** 'shift' applies deterministic patient-scoped offset; 'year-only' keeps YYYY; 'redact' tokenizes dates. Default 'shift'. */
  dateStrategy?: 'shift' | 'year-only' | 'redact';
  /** Deterministic seed for date shifting (if omitted, generated per vault/call). */
  dateShiftDays?: number;
  /** Cap ages over 89 to '90+' per HIPAA Safe Harbor (default true). */
  capAgeOver89?: boolean;
  /** Preserve clinical coding fields (coding, code, system, valueQuantity, unit). Default true. */
  preserveClinicalCodes?: boolean;
}
