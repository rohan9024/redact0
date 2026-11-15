import { Vault } from './engine';
import type { RedactOptions } from './types';

export interface LoggerRedactorOptions extends RedactOptions {
  /** Use fixed masking instead of numbered vault tokens by default for logs ('mask' | 'hash' | 'bracket'). Default 'mask'. */
  logTokenFormat?: 'mask' | 'hash' | 'bracket';
}

function createLogVault(options: LoggerRedactorOptions): Vault {
  return new Vault({
    ...options,
    tokenFormat: options.tokenFormat ?? options.logTokenFormat ?? 'mask',
  });
}

/**
 * Drop-in configuration object for Pino (`pino(pinoRedactor())`).
 * Scrubs all log arguments, nested objects, Error stacks/messages, and HTTP request headers.
 */
export function pinoRedactor(options: LoggerRedactorOptions = {}) {
  const vault = createLogVault(options);

  return {
    hooks: {
      logMethod(
        this: unknown,
        inputArgs: unknown[],
        method: (...args: unknown[]) => void
      ) {
        const scrubbed = inputArgs.map((arg) => vault.redact(arg).value);
        return method.apply(this, scrubbed);
      },
    },
    serializers: {
      err(err: unknown) {
        return vault.redact(err).value;
      },
      req(req: Record<string, unknown>) {
        return vault.redact(req).value;
      },
      res(res: Record<string, unknown>) {
        return vault.redact(res).value;
      },
    },
  };
}

/**
 * Drop-in Winston format compatible with `winston.format.combine(winstonFormat(), ...)`.
 */
export function winstonFormat(options: LoggerRedactorOptions = {}) {
  const vault = createLogVault(options);
  return {
    transform(info: Record<string, unknown>) {
      return vault.redactObject(info).value;
    },
  };
}

/**
 * Sanitizes OpenTelemetry span/metric attribute records.
 */
export function redactAttributes<T extends Record<string, unknown>>(
  attributes: T,
  options: LoggerRedactorOptions = {}
): T {
  const vault = createLogVault(options);
  return vault.redactObject(attributes).value;
}

/**
 * Patches global `console.log/info/warn/error/debug` in-place; returns restore function.
 */
export function patchConsole(options: LoggerRedactorOptions = {}): () => void {
  const vault = createLogVault(options);
  const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
  const originals = new Map<string, (...args: unknown[]) => void>();

  for (const m of methods) {
    const orig = console[m].bind(console);
    originals.set(m, orig);
    console[m] = (...args: unknown[]) => {
      orig(...args.map((a) => vault.redact(a).value));
    };
  }

  return () => {
    for (const [m, orig] of originals.entries()) {
      (console as unknown as Record<string, unknown>)[m] = orig;
    }
  };
}
