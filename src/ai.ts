import { Vault } from './engine';
import { createSSERestorer, createStreamRestorer } from './stream';
import type { RedactOptions } from './types';

export interface AiAdapterOptions extends RedactOptions {
  /** Shared vault instance across turns; if omitted, creates an isolated per-request vault. */
  vault?: Vault;
  /** Restore tokens inside generated text & streamed deltas (default true). */
  restoreOutput?: boolean;
  /** Restore tokens inside LLM-generated tool-call arguments before local execution (default true). */
  rehydrateToolCalls?: boolean;
  /** Vercel AI SDK middleware specification version ('v2' | 'v3' | 'v4'). Default 'v3'. */
  specificationVersion?: 'v2' | 'v3' | 'v4';
}

const promptVaultMap = new WeakMap<object, Vault>();

function getOrCreateRequestVault(
  params: Record<string, unknown>,
  options: AiAdapterOptions
): Vault {
  if (options.vault) return options.vault;
  const fromParams = promptVaultMap.get(params);
  if (fromParams) return fromParams;
  if (params.prompt && typeof params.prompt === 'object') {
    const fromPrompt = promptVaultMap.get(params.prompt as object);
    if (fromPrompt) return fromPrompt;
  }
  const fresh = new Vault(options);
  promptVaultMap.set(params, fresh);
  if (params.prompt && typeof params.prompt === 'object') {
    promptVaultMap.set(params.prompt as object, fresh);
  }
  return fresh;
}

/**
 * Drop-in LanguageModelMiddleware compatible with Vercel AI SDK v5 (v2 spec),
 * v6 (v3 spec), and v7 (v4 spec) via zero-dep structural typing.
 *
 * Usage:
 *   const model = wrapLanguageModel({ model: openai('gpt-4o'), middleware: redactMiddleware() });
 */
export function redactMiddleware(options: AiAdapterOptions = {}) {
  const restoreOut = options.restoreOutput ?? true;
  const rehydrateTools = options.rehydrateToolCalls ?? true;
  const specVersion = options.specificationVersion ?? 'v3';

  return {
    specificationVersion: specVersion,

    async transformParams({ params }: { params: Record<string, unknown> }) {
      const vault = options.vault ?? new Vault(options);
      const nextParams = { ...params };

      if (Array.isArray(params.prompt)) {
        const nextPrompt = vault.redactObject(params.prompt).value;
        nextParams.prompt = nextPrompt;
        promptVaultMap.set(nextPrompt as object, vault);
      }

      promptVaultMap.set(nextParams, vault);
      return nextParams;
    },

    async wrapGenerate({
      doGenerate,
      params,
    }: {
      doGenerate: () => Promise<Record<string, unknown>>;
      params: Record<string, unknown>;
    }) {
      const vault = getOrCreateRequestVault(params, options);
      const result = await doGenerate();
      if (!restoreOut) return result;

      const out = { ...result };

      if (typeof out.text === 'string') {
        out.text = vault.restore(out.text);
      }

      if (Array.isArray(out.content)) {
        out.content = out.content.map((part) => {
          if (!part || typeof part !== 'object') return part;
          const p = { ...(part as Record<string, unknown>) };
          if ((p.type === 'text' || p.type === 'reasoning') && typeof p.text === 'string') {
            p.text = vault.restore(p.text);
          } else if (rehydrateTools && p.type === 'tool-call') {
            if (typeof p.input === 'string') p.input = vault.restore(p.input);
            else if (p.input && typeof p.input === 'object') p.input = vault.restoreObject(p.input);
            if (typeof p.args === 'string') p.args = vault.restore(p.args);
            else if (p.args && typeof p.args === 'object') p.args = vault.restoreObject(p.args);
          }
          return p;
        });
      }

      return out;
    },

    async wrapStream({
      doStream,
      params,
    }: {
      doStream: () => Promise<{ stream: ReadableStream<Record<string, unknown>> } & Record<string, unknown>>;
      params: Record<string, unknown>;
    }) {
      const vault = getOrCreateRequestVault(params, options);
      const { stream, ...rest } = await doStream();
      if (!restoreOut) return { stream, ...rest };

      const textRestorer = createStreamRestorer(vault);
      const reasoningRestorer = createStreamRestorer(vault);

      const transformed = stream.pipeThrough(
        new TransformStream<Record<string, unknown>, Record<string, unknown>>({
          transform(chunk, controller) {
            if (!chunk || typeof chunk !== 'object') {
              controller.enqueue(chunk);
              return;
            }
            const c = { ...chunk };

            if (c.type === 'text-delta') {
              // Supports both v6/v7 (`delta`) and v5 (`textDelta`)
              if (typeof c.delta === 'string') {
                const out = textRestorer.push(c.delta);
                if (out.length > 0) controller.enqueue({ ...c, delta: out });
                return;
              }
              if (typeof c.textDelta === 'string') {
                const out = textRestorer.push(c.textDelta);
                if (out.length > 0) controller.enqueue({ ...c, textDelta: out });
                return;
              }
            }

            if (c.type === 'reasoning-delta' && typeof c.delta === 'string') {
              const out = reasoningRestorer.push(c.delta);
              if (out.length > 0) controller.enqueue({ ...c, delta: out });
              return;
            }

            if (rehydrateTools && c.type === 'tool-call') {
              if (typeof c.input === 'string') c.input = vault.restore(c.input);
              if (typeof c.args === 'string') c.args = vault.restore(c.args);
            }

            if (c.type === 'finish' || c.type === 'text-end') {
              const tailText = textRestorer.flush();
              if (tailText.length > 0) {
                controller.enqueue({ type: 'text-delta', id: c.id ?? '0', delta: tailText, textDelta: tailText });
              }
              const tailReason = reasoningRestorer.flush();
              if (tailReason.length > 0) {
                controller.enqueue({ type: 'reasoning-delta', id: c.id ?? '0', delta: tailReason });
              }
            }

            controller.enqueue(c);
          },
          flush(controller) {
            const tailText = textRestorer.flush();
            if (tailText.length > 0) {
              controller.enqueue({ type: 'text-delta', id: '0', delta: tailText, textDelta: tailText });
            }
          },
        })
      );

      return { stream: transformed, ...rest };
    },
  };
}

/**
 * Wraps an OpenAI SDK client instance (`new OpenAI()`) to scrub messages/input
 * and transparently restore responses & streaming async iterables.
 */
export function wrapOpenAI<T extends Record<string, any>>(client: T, options: AiAdapterOptions = {}): T {
  const restoreOut = options.restoreOutput ?? true;

  const wrapCreate = (origFn: (...args: any[]) => Promise<any>, thisArg: any) => {
    return async (body: Record<string, any>, reqOpts?: unknown) => {
      const vault = options.vault ?? new Vault(options);
      const safeBody = vault.redactObject(body).value;
      const response = await origFn.call(thisArg, safeBody, reqOpts);
      if (!restoreOut || !response) return response;

      if (typeof response[Symbol.asyncIterator] === 'function') {
        const restorer = createStreamRestorer(vault);
        async function* restoredStream() {
          for await (const chunk of response) {
            const cloned = structuredCloneSafe(chunk);
            const delta = cloned?.choices?.[0]?.delta;
            if (delta && typeof delta.content === 'string') {
              delta.content = restorer.push(delta.content);
            } else if (cloned?.type === 'response.output_text.delta' && typeof cloned.delta === 'string') {
              cloned.delta = restorer.push(cloned.delta);
            }
            yield cloned;
          }
          const tail = restorer.flush();
          if (tail.length > 0) {
            yield { choices: [{ index: 0, delta: { content: tail } }] };
          }
        }
        return restoredStream();
      }

      return vault.restoreObject(response);
    };
  };

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === 'chat' && target.chat?.completions?.create) {
        return new Proxy(target.chat, {
          get(chatTarget, chatProp) {
            if (chatProp === 'completions') {
              return new Proxy(chatTarget.completions, {
                get(compTarget, compProp) {
                  if (compProp === 'create') {
                    return wrapCreate(compTarget.create, compTarget);
                  }
                  return Reflect.get(compTarget, compProp);
                },
              });
            }
            return Reflect.get(chatTarget, chatProp);
          },
        });
      }
      if (prop === 'responses' && target.responses?.create) {
        return new Proxy(target.responses, {
          get(respTarget, respProp) {
            if (respProp === 'create') {
              return wrapCreate(respTarget.create, respTarget);
            }
            return Reflect.get(respTarget, respProp);
          },
        });
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/**
 * Wraps an Anthropic SDK client instance (`new Anthropic()`) to scrub outgoing messages
 * and restore non-streaming & streaming message responses.
 */
export function wrapAnthropic<T extends Record<string, any>>(client: T, options: AiAdapterOptions = {}): T {
  const restoreOut = options.restoreOutput ?? true;

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === 'messages' && target.messages?.create) {
        return new Proxy(target.messages, {
          get(msgTarget, msgProp) {
            if (msgProp === 'create') {
              return async (body: Record<string, any>, reqOpts?: unknown) => {
                const vault = options.vault ?? new Vault(options);
                const safeBody = vault.redactObject(body).value;
                const response = await msgTarget.create.call(msgTarget, safeBody, reqOpts);
                if (!restoreOut || !response) return response;

                if (typeof response[Symbol.asyncIterator] === 'function') {
                  const restorer = createStreamRestorer(vault);
                  async function* restoredStream() {
                    for await (const ev of response) {
                      const cloned = structuredCloneSafe(ev);
                      if (
                        cloned?.type === 'content_block_delta' &&
                        cloned?.delta?.type === 'text_delta' &&
                        typeof cloned.delta.text === 'string'
                      ) {
                        cloned.delta.text = restorer.push(cloned.delta.text);
                      }
                      if (cloned?.type === 'message_stop') {
                        const tail = restorer.flush();
                        if (tail.length > 0) {
                          yield {
                            type: 'content_block_delta',
                            index: 0,
                            delta: { type: 'text_delta', text: tail },
                          };
                        }
                      }
                      yield cloned;
                    }
                  }
                  return restoredStream();
                }

                return vault.restoreObject(response);
              };
            }
            return Reflect.get(msgTarget, msgProp);
          },
        });
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/**
 * Universal fetch() wrapper that scrubs JSON request payloads and restores JSON or SSE responses.
 */
export function wrapFetch(
  fetchFn: typeof fetch = globalThis.fetch,
  options: AiAdapterOptions = {}
): typeof fetch {
  const restoreOut = options.restoreOutput ?? true;

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const vault = options.vault ?? new Vault(options);
    let nextInit = init;

    if (init && typeof init.body === 'string') {
      try {
        const parsed = JSON.parse(init.body);
        const safeObj = vault.redactObject(parsed).value;
        nextInit = { ...init, body: JSON.stringify(safeObj) };
      } catch {
        nextInit = { ...init, body: vault.redactText(init.body).value };
      }
    }

    const res = await fetchFn(input, nextInit);
    if (!restoreOut) return res;

    const ct = res.headers.get('content-type') ?? '';
    if (ct.includes('text/event-stream') && res.body) {
      const sse = createSSERestorer(vault);
      const stream = res.body.pipeThrough(sse.createByteTransformStream());
      return new Response(stream, {
        status: res.status,
        statusText: res.statusText,
        headers: res.headers,
      });
    }

    if (ct.includes('application/json')) {
      const rawText = await res.text();
      try {
        const parsed = JSON.parse(rawText);
        const restored = vault.restoreObject(parsed);
        return new Response(JSON.stringify(restored), {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers,
        });
      } catch {
        return new Response(vault.restore(rawText), {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers,
        });
      }
    }

    return res;
  };
}

function structuredCloneSafe<T>(val: T): T {
  try {
    return structuredClone(val);
  } catch {
    return JSON.parse(JSON.stringify(val));
  }
}
