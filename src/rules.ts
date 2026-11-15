import type { DetectorRule, PolicyPreset } from './types';
import {
  isValidAadhaar,
  isValidDeTaxId,
  isValidDea,
  isValidIban,
  isValidIpv4,
  isValidJwt,
  isValidLuhn,
  isValidMbi,
  isValidNhs,
  isValidNpi,
  isValidSsn,
  shannonEntropy,
} from './validators';

const ALL_PRESETS: readonly PolicyPreset[] = ['default', 'secrets', 'hipaa', 'gdpr', 'strict'];
const PII_PRESETS: readonly PolicyPreset[] = ['default', 'hipaa', 'gdpr', 'strict'];
const HIPAA_STRICT: readonly PolicyPreset[] = ['hipaa', 'strict'];
const GDPR_STRICT: readonly PolicyPreset[] = ['gdpr', 'strict'];

export const BUILTIN_RULES: readonly DetectorRule[] = [
  // ---------------------------------------------------------------------------
  // 1. Secrets, Credentials, Keys & Connection URIs (Priority 80..100)
  // ---------------------------------------------------------------------------
  {
    id: 'pem-private-key',
    category: 'PRIVATE_KEY',
    priority: 100,
    presets: ALL_PRESETS,
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]{16,8192}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    id: 'connection-uri-password',
    category: 'CONNECTION_URI',
    priority: 96,
    presets: ALL_PRESETS,
    captureGroup: 1,
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|clickhouse|cockroachdb):\/\/[^:\s/@]+:([^@\s/]{3,256})@[^\s"'<>]+/gi,
  },
  {
    id: 'anthropic-key',
    category: 'API_KEY',
    priority: 95,
    presets: ALL_PRESETS,
    pattern: /\bsk-ant-(?:api\d{2}|admin\d{2}|oat\d{2}|[a-z0-9]+)-[A-Za-z0-9_-]{24,}\b/g,
  },
  {
    id: 'openai-key',
    category: 'API_KEY',
    priority: 95,
    presets: ALL_PRESETS,
    pattern: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{24,}\b|\bsk-[A-Za-z0-9]{16,}T3BlbkFJ[A-Za-z0-9]{16,}\b/g,
  },
  {
    id: 'github-token',
    category: 'API_KEY',
    priority: 95,
    presets: ALL_PRESETS,
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{40,})\b/g,
  },
  {
    id: 'aws-access-key',
    category: 'API_KEY',
    priority: 94,
    presets: ALL_PRESETS,
    pattern: /\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'stripe-secret',
    category: 'API_KEY',
    priority: 94,
    presets: ALL_PRESETS,
    pattern: /\b(?:sk_live|rk_live|whsec)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: 'google-api-key',
    category: 'API_KEY',
    priority: 93,
    presets: ALL_PRESETS,
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: 'slack-token',
    category: 'TOKEN',
    priority: 93,
    presets: ALL_PRESETS,
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{14,}\b|https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
  },
  {
    id: 'discord-webhook',
    category: 'SECRET',
    priority: 92,
    presets: ALL_PRESETS,
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{16,22}\/[A-Za-z0-9_-]{40,}/g,
  },
  {
    id: 'provider-prefixed-keys',
    category: 'API_KEY',
    priority: 92,
    presets: ALL_PRESETS,
    pattern:
      /\b(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{36,}|xai-[A-Za-z0-9]{36,}|pplx-[A-Za-z0-9]{36,}|sbp_[A-Za-z0-9]{36,}|sb_secret_[A-Za-z0-9_-]{24,}|re_[A-Za-z0-9_]{24,}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
  },
  {
    id: 'jwt-token',
    category: 'JWT',
    priority: 90,
    presets: ALL_PRESETS,
    pattern: /\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\b/g,
    validate: (val) => isValidJwt(val),
  },
  {
    id: 'bearer-auth-header',
    category: 'TOKEN',
    priority: 88,
    presets: ALL_PRESETS,
    captureGroup: 1,
    pattern: /\b(?:Authorization|Proxy-Authorization)\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{12,})["']?/gi,
  },
  {
    id: 'contextual-secret-assignment',
    category: 'SECRET',
    priority: 72,
    presets: ALL_PRESETS,
    captureGroup: 1,
    pattern:
      /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|aws_secret_access_key|password|passwd|pwd|signing[_-]?secret)\b\s*[:=]\s*["']?([^\s"',;}{]{10,128})["']?/gi,
    validate: (val) => !val.startsWith('[') && !val.startsWith('<') && shannonEntropy(val) >= 2.8,
  },

  // ---------------------------------------------------------------------------
  // 2. Healthcare / HIPAA Identifiers (Priority 70..85)
  // ---------------------------------------------------------------------------
  {
    id: 'medicare-mbi',
    category: 'MBI',
    priority: 84,
    presets: HIPAA_STRICT,
    pattern: /\b[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]-?\d[AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]-?\d[AC-HJKMNP-RT-Y]{2}\d{2}\b/gi,
    validate: (val) => isValidMbi(val),
  },
  {
    id: 'us-dea',
    category: 'DEA',
    priority: 83,
    presets: HIPAA_STRICT,
    pattern: /\b[ABFGMPRX][A-Z9]\d{7}\b/g,
    validate: (val) => isValidDea(val),
  },
  {
    id: 'us-npi',
    category: 'NPI',
    priority: 80,
    presets: HIPAA_STRICT,
    contextWindow: 40,
    contextRegex: /\b(?:npi|provider|prescriber|practitioner|physician)\b/i,
    pattern: /\b[12]\d{9}\b/g,
    validate: (val) => isValidNpi(val),
  },
  {
    id: 'uk-nhs-number',
    category: 'NHS',
    priority: 80,
    presets: ['hipaa', 'gdpr', 'strict'],
    contextWindow: 40,
    contextRegex: /\b(?:nhs|patient|health|care|medical)\b/i,
    pattern: /\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b/g,
    validate: (val) => isValidNhs(val),
  },
  {
    id: 'medical-record-number',
    category: 'MRN',
    priority: 78,
    presets: HIPAA_STRICT,
    captureGroup: 1,
    pattern: /\b(?:mrn|medical[\s_-]?record(?:[\s_-]?number)?|patient[\s_-]?id)\s*[:=#]?\s*([A-Z0-9-]{5,20})\b/gi,
  },

  // ---------------------------------------------------------------------------
  // 3. Financial & National IDs (Priority 70..85)
  // ---------------------------------------------------------------------------
  {
    id: 'iban',
    category: 'IBAN',
    priority: 84,
    presets: PII_PRESETS,
    pattern: /\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){11,30}\b/g,
    validate: (val) => isValidIban(val),
  },
  {
    id: 'credit-card',
    category: 'CREDIT_CARD',
    priority: 82,
    presets: PII_PRESETS,
    pattern: /\b(?:\d[ -]?){13,18}\d\b/g,
    validate: (val) => {
      const digits = val.replace(/\D/g, '');
      return /^(?:4\d{12}(?:\d{3})?(?:\d{3})?|5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01]|720)\d{12}|3[47]\d{13}|6(?:011|5\d\d)\d{12}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11})$/.test(
        digits
      ) && isValidLuhn(digits);
    },
  },
  {
    id: 'us-ssn',
    category: 'SSN',
    priority: 81,
    presets: PII_PRESETS,
    pattern: /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b|\b\d{9}\b/g,
    validate: (val, ctx) => isValidSsn(val, ctx),
  },
  {
    id: 'aadhaar-in',
    category: 'AADHAAR',
    priority: 76,
    presets: ['gdpr', 'strict'],
    contextWindow: 40,
    contextRegex: /\b(?:aadhaar|aadhar|uidai)\b/i,
    pattern: /\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    validate: (val) => isValidAadhaar(val),
  },
  {
    id: 'de-tax-id',
    category: 'TAX_ID',
    priority: 76,
    presets: GDPR_STRICT,
    contextWindow: 45,
    contextRegex: /\b(?:steuer|tax|tin|idnr|identifikationsnummer)\b/i,
    pattern: /\b[1-9]\d{10}\b/g,
    validate: (val) => isValidDeTaxId(val),
  },

  // ---------------------------------------------------------------------------
  // 4. Core Contact, Network & Contextual PII (Priority 45..75)
  // ---------------------------------------------------------------------------
  {
    id: 'email',
    category: 'EMAIL',
    priority: 75,
    presets: PII_PRESETS,
    pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b/g,
  },
  {
    id: 'phone',
    category: 'PHONE',
    priority: 65,
    presets: PII_PRESETS,
    pattern:
      /(?:\+\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)[-.\s]?|\b\d{3}[-.\s])\d{3,4}[-.\s]\d{4}\b|\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g,
    validate: (val) => {
      const digits = val.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15 && !/^(\d)\1+$/.test(digits);
    },
  },
  {
    id: 'ipv4',
    category: 'IP_ADDRESS',
    priority: 60,
    presets: PII_PRESETS,
    pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
    validate: (val) => isValidIpv4(val),
  },
  {
    id: 'ipv6',
    category: 'IP_ADDRESS',
    priority: 58,
    presets: ['hipaa', 'gdpr', 'strict'],
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g,
  },
  {
    id: 'mac-address',
    category: 'MAC_ADDRESS',
    priority: 58,
    presets: ['hipaa', 'gdpr', 'strict'],
    pattern: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    id: 'labeled-person-name',
    category: 'PERSON',
    priority: 55,
    presets: ['hipaa', 'strict'],
    captureGroup: 1,
    pattern:
      /\b(?:Patient(?:\s+Name)?|Dr\.|Doctor|Clinician|Provider|Mr\.|Mrs\.|Ms\.|Full\s+Name|Beneficiary)\s*[:.]?\s*([A-Z][a-z]{1,24}(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]{1,24}){1,2})/g,
  },
  {
    id: 'dob-or-clinical-date',
    category: 'DATE',
    priority: 52,
    presets: HIPAA_STRICT,
    contextWindow: 40,
    contextRegex: /\b(?:dob|birth|born|admit(?:ted)?|discharg(?:e|ed)|visit|encounter|date)\b/i,
    pattern: /\b(?:\d{4}-\d{2}-\d{2}|(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2})\b/g,
  },
];
