import { hmacSha256Hex, randomNonceHex, sha256Hex } from './crypto';
import { BUILTIN_RULES } from './rules';
import type {
  CustomRuleInput,
  DetectorRule,
  EntityCategory,
  Finding,
  PolicyPreset,
  RedactOptions,
  RedactResult,
  RuleMatchContext,
  TokenFormat,
  VaultSnapshot,
} from './types';
import { isPrivateOrLoopbackIpv4 } from './validators';

const DEFAULT_SENSITIVE_KEY_RE =
  /^(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|authorization|cookie|set-cookie|x-api-key|client[_-]?secret|private[_-]?key|ssn|social[_-]?security(?:[_-]?number)?|cvv|cvc|pin|iban|dob|birth[_-]?date|mrn)$/i;

const RESERVED_TOKEN_RE = /\[[A-Z_]+_\d+(?:#[a-f0-9]{4,8})?\]|<[A-Z_]+_\d+(?:#[a-f0-9]{4,8})?>/g;

function normalizeCategoryFromKey(key: string): EntityCategory {
  const k = key.toLowerCase();
  if (k.includes('ssn') || k.includes('social')) return 'SSN';
  if (k.includes('iban')) return 'IBAN';
  if (k.includes('mrn')) return 'MRN';
  if (k.includes('dob') || k.includes('birth')) return 'DATE';
  if (k.includes('password') || k.includes('passwd') || k.includes('secret') || k === 'cvv' || k === 'cvc' || k === 'pin') {
    return 'SECRET';
  }
  if (k.includes('token') || k === 'authorization' || k === 'cookie' || k === 'set-cookie') return 'TOKEN';
  if (k.includes('key')) return 'API_KEY';
  return 'CUSTOM';
}

function resolveActiveRules(options: RedactOptions): DetectorRule[] {
  const preset: PolicyPreset = options.preset ?? 'default';
  const base = options.rules ? [...options.rules] : BUILTIN_RULES.filter((r) => r.presets.includes(preset));

  const custom: DetectorRule[] = (options.customRules ?? []).map((c: CustomRuleInput) => ({
    id: c.id,
    category: c.category ?? 'CUSTOM',
    pattern: c.pattern,
    captureGroup: c.captureGroup,
    priority: c.priority ?? 85,
    presets: ['default', 'secrets', 'hipaa', 'gdpr', 'strict'],
    validate: c.validate,
  }));

  let merged = [...custom, ...base];
  if (options.categories?.length) {
    const allowed = new Set(options.categories);
    merged = merged.filter((r) => allowed.has(r.category));
  }
  if (options.excludeCategories?.length) {
    const blocked = new Set(options.excludeCategories);
    merged = merged.filter((r) => !blocked.has(r.category));
  }
  return merged;
}

interface CandidateMatch {
  id: string;
  category: EntityCategory;
  priority: number;
  start: number;
  end: number;
  value: string;
}

function collectLiteralMatches(text: string, literals: readonly string[]): CandidateMatch[] {
  const out: CandidateMatch[] = [];
  for (const lit of literals) {
    if (!lit || lit.length < 4) continue;
    let idx = 0;
    while (true) {
      const found = text.indexOf(lit, idx);
      if (found === -1) break;
      out.push({
        id: 'literal-secret',
        category: 'SECRET',
        priority: 99,
        start: found,
        end: found + lit.length,
        value: lit,
      });
      idx = found + lit.length;
    }
  }
  return out;
}

function collectMatches(text: string, rules: readonly DetectorRule[], options: RedactOptions): CandidateMatch[] {
  const candidates: CandidateMatch[] = [];
  const allowSet = options.allowlist ? new Set(options.allowlist) : undefined;
  const redactPrivateIps =
    options.redactPrivateIps ?? (options.preset === 'strict' || options.preset === 'hipaa');

  if (options.literals?.length) {
    candidates.push(...collectLiteralMatches(text, options.literals));
  }

  for (const rule of rules) {
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
    const re = new RegExp(rule.pattern.source, flags);
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }

      let start = m.index;
      let value = m[0];

      if (rule.captureGroup !== undefined && m[rule.captureGroup] !== undefined) {
        const groupVal = m[rule.captureGroup]!;
        const innerOffset = m[0].indexOf(groupVal);
        if (innerOffset !== -1) {
          start = m.index + innerOffset;
          value = groupVal;
        }
      }

      const end = start + value.length;
      if (allowSet?.has(value)) continue;

      if (rule.id === 'ipv4' && !redactPrivateIps && isPrivateOrLoopbackIpv4(value)) {
        continue;
      }

      if (rule.contextRegex) {
        const win = rule.contextWindow ?? 40;
        const left = text.slice(Math.max(0, start - win), start);
        const right = text.slice(end, Math.min(text.length, end + win));
        if (!rule.contextRegex.test(left) && !rule.contextRegex.test(right)) {
          continue;
        }
      }

      if (rule.validate) {
        const ctx: RuleMatchContext = { fullText: text, match: m, start, end, value };
        if (!rule.validate(value, ctx)) continue;
      }

      candidates.push({
        id: rule.id,
        category: rule.category,
        priority: rule.priority,
        start,
        end,
        value,
      });
    }
  }

  candidates.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted: CandidateMatch[] = [];
  for (const cand of candidates) {
    let overlaps = false;
    for (const acc of accepted) {
      if (cand.start < acc.end && cand.end > acc.start) {
        overlaps = true;
        break;
      }
    }
    if (!overlaps) accepted.push(cand);
  }

  accepted.sort((a, b) => a.start - b.start);
  return accepted;
}

export class Vault {
  private readonly options: RedactOptions;
  private readonly rules: DetectorRule[];
  private readonly tokenFormat: TokenFormat;
  private readonly vaultKey: string;
  private readonly sensitiveKeyRe: RegExp;

  private readonly forward = new Map<string, string>();
  private readonly reverse = new Map<string, { category: EntityCategory; value: string }>();
  private readonly counters = new Map<string, number>();
  private readonly reservedTokens = new Set<string>();
  private _version = 0;

  constructor(options: RedactOptions = {}) {
    this.options = options;
    this.rules = resolveActiveRules(options);
    this.tokenFormat = options.tokenFormat ?? 'bracket';
    this.vaultKey = options.secret ?? randomNonceHex(16);
    this.sensitiveKeyRe = options.sensitiveKeys?.length
      ? new RegExp(
          `^(?:${options.sensitiveKeys.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})$`,
          'i'
        )
      : DEFAULT_SENSITIVE_KEY_RE;
  }

  get version(): number {
    return this._version;
  }

  private fingerprint(value: string): string {
    return hmacSha256Hex(this.vaultKey, value, 12);
  }

  private reserveExistingTokens(text: string): void {
    const re = new RegExp(RESERVED_TOKEN_RE.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (!this.reverse.has(m[0])) {
        this.reservedTokens.add(m[0]);
      }
    }
  }

  tokenize(category: EntityCategory, value: string): string {
    const composite = `${category}:${value}`;
    const existing = this.forward.get(composite);
    if (existing !== undefined) return existing;

    if (this.tokenFormat === 'mask') {
      const ch = this.options.maskChar ?? '*';
      return ch.repeat(Math.min(Math.max(value.length, 4), 16));
    }

    if (this.tokenFormat === 'hash') {
      const digest = hmacSha256Hex(this.vaultKey, composite, 8);
      const tok = `[${category}:${digest}]`;
      this.forward.set(composite, tok);
      this.reverse.set(tok, { category, value });
      this._version += 1;
      return tok;
    }

    let idx = this.counters.get(category) ?? 0;
    let tok: string;
    do {
      idx += 1;
      if (this.tokenFormat === 'angle') {
        tok = `<${category}_${idx}>`;
      } else if (this.tokenFormat === 'signed') {
        const tag = hmacSha256Hex(this.vaultKey, `${category}:${idx}:${value}`, 4);
        tok = `[${category}_${idx}#${tag}]`;
      } else {
        tok = `[${category}_${idx}]`;
      }
    } while (this.reservedTokens.has(tok) || this.reverse.has(tok));

    this.counters.set(category, idx);
    this.forward.set(composite, tok);
    this.reverse.set(tok, { category, value });
    this._version += 1;
    return tok;
  }

  scan(text: string): Finding[] {
    if (typeof text !== 'string' || text.length === 0) return [];
    const matches = collectMatches(text, this.rules, this.options);
    return matches.map((m) => ({
      id: m.id,
      category: m.category,
      start: m.start,
      end: m.end,
      token: `[${m.category}]`,
      length: m.value.length,
      fingerprint: sha256Hex(m.value, 12),
    }));
  }

  redactText(text: string): RedactResult<string> {
    if (typeof text !== 'string' || text.length === 0) {
      return { value: text, findings: [], count: 0 };
    }
    this.reserveExistingTokens(text);
    const matches = collectMatches(text, this.rules, this.options);
    if (matches.length === 0) {
      return { value: text, findings: [], count: 0 };
    }

    let out = '';
    let cursor = 0;
    const findings: Finding[] = [];

    for (const m of matches) {
      out += text.slice(cursor, m.start);
      const token = this.tokenize(m.category, m.value);
      out += token;
      cursor = m.end;
      findings.push({
        id: m.id,
        category: m.category,
        start: m.start,
        end: m.end,
        token,
        length: m.value.length,
        fingerprint: this.fingerprint(m.value),
      });
    }
    out += text.slice(cursor);

    return { value: out, findings, count: findings.length };
  }

  redactObject<T>(input: T): RedactResult<T> {
    const findings: Finding[] = [];
    const maxDepth = this.options.maxDepth ?? 32;
    const seen = new WeakMap<object, unknown>();

    const walk = (node: unknown, depth: number, keyHint?: string): unknown => {
      if (node === null || node === undefined) return node;

      if (typeof node === 'string') {
        if (keyHint && this.sensitiveKeyRe.test(keyHint) && node.length > 0 && !this.reverse.has(node)) {
          const cat = normalizeCategoryFromKey(keyHint);
          const token = this.tokenize(cat, node);
          findings.push({
            id: 'sensitive-key',
            category: cat,
            start: 0,
            end: node.length,
            token,
            length: node.length,
            fingerprint: this.fingerprint(node),
          });
          return token;
        }
        const res = this.redactText(node);
        if (res.count > 0) findings.push(...res.findings);
        return res.value;
      }

      if (typeof node !== 'object') return node;
      if (depth >= maxDepth) return '[MAX_DEPTH_TRUNCATED]';

      if (seen.has(node)) return seen.get(node);

      if (node instanceof Date) return new Date(node.getTime());

      if (node instanceof RegExp) return new RegExp(node.source, node.flags);

      if (node instanceof URL) {
        const cloned = new URL(node.toString());
        if (cloned.password) {
          cloned.password = this.tokenize('SECRET', cloned.password);
        }
        const paramsToUpdate: Array<[string, string]> = [];
        cloned.searchParams.forEach((val, key) => {
          paramsToUpdate.push([key, val]);
        });
        for (const [qpKey, qpVal] of paramsToUpdate) {
          if (this.sensitiveKeyRe.test(qpKey) && qpVal) {
            cloned.searchParams.set(qpKey, this.tokenize(normalizeCategoryFromKey(qpKey), qpVal));
          } else {
            const res = this.redactText(qpVal);
            if (res.count > 0) {
              findings.push(...res.findings);
              cloned.searchParams.set(qpKey, res.value);
            }
          }
        }
        return cloned;
      }

      if (typeof Headers !== 'undefined' && node instanceof Headers) {
        const cloned = new Headers();
        node.forEach((v, k) => {
          cloned.set(k, walk(v, depth + 1, k) as string);
        });
        return cloned;
      }

      if (node instanceof Error) {
        const safeErr: Record<string, unknown> = {
          name: node.name,
          message:
            this.options.redactErrors !== false ? walk(node.message, depth + 1) : node.message,
        };
        if (node.stack !== undefined) {
          safeErr.stack =
            this.options.redactErrors !== false ? walk(node.stack, depth + 1) : node.stack;
        }
        if ('cause' in node && (node as { cause?: unknown }).cause !== undefined) {
          safeErr.cause = walk((node as { cause?: unknown }).cause, depth + 1);
        }
        for (const k of Object.keys(node)) {
          safeErr[k] = walk((node as unknown as Record<string, unknown>)[k], depth + 1, k);
        }
        return safeErr;
      }

      if (Array.isArray(node)) {
        const arr: unknown[] = [];
        seen.set(node, arr);
        for (let i = 0; i < node.length; i++) {
          arr.push(walk(node[i], depth + 1, keyHint));
        }
        return arr;
      }

      if (node instanceof Map) {
        const m = new Map();
        seen.set(node, m);
        for (const [k, v] of node.entries()) {
          const hint = typeof k === 'string' ? k : undefined;
          m.set(walk(k, depth + 1), walk(v, depth + 1, hint));
        }
        return m;
      }

      if (node instanceof Set) {
        const s = new Set();
        seen.set(node, s);
        for (const v of node.values()) {
          s.add(walk(v, depth + 1));
        }
        return s;
      }

      const obj: Record<string, unknown> = {};
      seen.set(node, obj);
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        obj[k] = walk(v, depth + 1, k);
      }
      return obj;
    };

    const value = walk(input, 0) as T;
    return { value, findings, count: findings.length };
  }

  redact<T>(input: T): RedactResult<T> {
    if (typeof input === 'string') {
      return this.redactText(input) as unknown as RedactResult<T>;
    }
    return this.redactObject(input);
  }

  restore(text: string): string {
    if (typeof text !== 'string' || text.length === 0 || this.reverse.size === 0) {
      return text;
    }
    const tokens = Array.from(this.reverse.keys()).sort((a, b) => b.length - a.length);
    const escaped = tokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const re = new RegExp(escaped.join('|'), 'g');
    return text.replace(re, (match) => this.reverse.get(match)?.value ?? match);
  }

  restoreObject<T>(input: T): T {
    const seen = new WeakMap<object, unknown>();
    const walk = (node: unknown, depth: number): unknown => {
      if (node === null || node === undefined) return node;
      if (typeof node === 'string') return this.restore(node);
      if (typeof node !== 'object' || depth >= 32) return node;
      if (seen.has(node)) return seen.get(node);
      if (Array.isArray(node)) {
        const arr: unknown[] = [];
        seen.set(node, arr);
        for (const item of node) arr.push(walk(item, depth + 1));
        return arr;
      }
      if (node instanceof Date || node instanceof RegExp || node instanceof URL) return node;
      const obj: Record<string, unknown> = {};
      seen.set(node, obj);
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        obj[k] = walk(v, depth + 1);
      }
      return obj;
    };
    return walk(input, 0) as T;
  }

  entries(): Array<{ token: string; category: EntityCategory; value: string }> {
    return Array.from(this.reverse.entries()).map(([token, meta]) => ({
      token,
      category: meta.category,
      value: meta.value,
    }));
  }

  export(): VaultSnapshot {
    const countersObj: Record<string, number> = {};
    for (const [k, v] of this.counters.entries()) countersObj[k] = v;
    return {
      version: 1,
      tokenFormat: this.tokenFormat,
      counters: countersObj,
      entries: this.entries(),
    };
  }

  static fromJSON(snapshot: VaultSnapshot, options: RedactOptions = {}): Vault {
    const vault = new Vault({ ...options, tokenFormat: snapshot.tokenFormat });
    for (const [k, v] of Object.entries(snapshot.counters)) {
      vault.counters.set(k, v);
    }
    for (const entry of snapshot.entries) {
      vault.forward.set(`${entry.category}:${entry.value}`, entry.token);
      vault.reverse.set(entry.token, { category: entry.category, value: entry.value });
    }
    vault._version += 1;
    return vault;
  }

  clear(): void {
    this.forward.clear();
    this.reverse.clear();
    this.counters.clear();
    this.reservedTokens.clear();
    this._version += 1;
  }
}

export function createVault(options: RedactOptions = {}): Vault {
  return new Vault(options);
}

export function redact<T>(input: T, options: RedactOptions = {}): T {
  const vault = new Vault(options);
  return vault.redact(input).value;
}

export function redactDetailed<T>(input: T, options: RedactOptions = {}): RedactResult<T> {
  const vault = new Vault(options);
  return vault.redact(input);
}

export function scan(text: string, options: RedactOptions = {}): Finding[] {
  const vault = new Vault(options);
  return vault.scan(text);
}