import type { Vault } from './engine';
import type { StreamRestorer } from './types';

/**
 * Chunk-boundary-safe reversible stream restorer.
 * Handles placeholder tokens split across arbitrary chunk boundaries (e.g. "[EM" + "AIL_1]")
 * as well as overlapping token prefixes (e.g. "TOK_1" vs "TOK_10") with minimal hold buffering.
 */
export function createStreamRestorer(vault: Vault): StreamRestorer {
  let cachedVersion = -1;
  let tokenMap = new Map<string, string>();
  let prefixes = new Set<string>();
  let firstChars = new Set<string>();
  let maxTokenLen = 0;

  const rebuildIndex = () => {
    if (vault.version === cachedVersion) return;
    cachedVersion = vault.version;
    tokenMap = new Map<string, string>();
    prefixes = new Set<string>();
    firstChars = new Set<string>();
    maxTokenLen = 0;

    for (const { token, value } of vault.entries()) {
      if (!token) continue;
      tokenMap.set(token, value);
      firstChars.add(token[0]!);
      if (token.length > maxTokenLen) maxTokenLen = token.length;
      // Record every strict prefix (1 .. token.length - 1)
      for (let len = 1; len < token.length; len++) {
        prefixes.add(token.slice(0, len));
      }
    }
  };

  let pending = '';

  const processBuffer = (isFlush: boolean): string => {
    rebuildIndex();
    if (pending.length === 0) return '';
    if (tokenMap.size === 0) {
      const out = pending;
      pending = '';
      return out;
    }

    let out = '';
    let pos = 0;

    while (pos < pending.length) {
      const ch = pending[pos]!;
      if (!firstChars.has(ch)) {
        out += ch;
        pos += 1;
        continue;
      }

      const remaining = pending.slice(pos);

      // If the entire remaining suffix could still extend into a longer token and we aren't flushing, hold it
      if (!isFlush && remaining.length < maxTokenLen && prefixes.has(remaining)) {
        break;
      }

      // Find longest exact token matching at `pos`
      const maxCheck = Math.min(maxTokenLen, remaining.length);
      let matchedToken: string | undefined;
      for (let len = maxCheck; len >= 1; len--) {
        const slice = remaining.slice(0, len);
        if (tokenMap.has(slice)) {
          matchedToken = slice;
          break;
        }
      }

      if (matchedToken !== undefined) {
        out += tokenMap.get(matchedToken)!;
        pos += matchedToken.length;
      } else {
        out += ch;
        pos += 1;
      }
    }

    pending = pending.slice(pos);
    return out;
  };

  return {
    push(chunk: string): string {
      if (!chunk) return '';
      pending += chunk;
      return processBuffer(false);
    },

    flush(): string {
      return processBuffer(true);
    },

    async *restoreIterable(source: AsyncIterable<string>): AsyncIterable<string> {
      for await (const chunk of source) {
        const out = this.push(chunk);
        if (out.length > 0) yield out;
      }
      const tail = this.flush();
      if (tail.length > 0) yield tail;
    },

    createTransformStream(): TransformStream<string, string> {
      return new TransformStream<string, string>({
        transform: (chunk, controller) => {
          const out = this.push(chunk);
          if (out.length > 0) controller.enqueue(out);
        },
        flush: (controller) => {
          const tail = this.flush();
          if (tail.length > 0) controller.enqueue(tail);
        },
      });
    },
  };
}

/**
 * Restores SSE payloads across OpenAI (Chat Completions & Responses),
 * Anthropic Messages, Gemini, and Vercel AI SDK UI/Data streams while preserving framing.
 */
export function createSSERestorer(vault: Vault) {
  const restorer = createStreamRestorer(vault);
  let lineBuffer = '';

  const restoreJsonPayload = (payload: Record<string, unknown>, isDone = false): boolean => {
    let changed = false;

    // OpenAI Chat Completions: choices[0].delta.content
    if (Array.isArray(payload.choices)) {
      for (const ch of payload.choices) {
        if (ch && typeof ch === 'object') {
          const delta = (ch as Record<string, unknown>).delta as Record<string, unknown> | undefined;
          if (delta && typeof delta.content === 'string') {
            delta.content = restorer.push(delta.content) + (isDone ? restorer.flush() : '');
            changed = true;
          }
        }
      }
    }

    // OpenAI Responses API / Vercel UI Stream: { type: 'response.output_text.delta' | 'text-delta', delta: '...' }
    if (
      typeof payload.delta === 'string' &&
      (payload.type === 'text-delta' ||
        payload.type === 'response.output_text.delta' ||
        payload.type === 'reasoning-delta')
    ) {
      payload.delta = restorer.push(payload.delta) + (isDone ? restorer.flush() : '');
      changed = true;
    }

    // Anthropic Messages SSE: { type: 'content_block_delta', delta: { type: 'text_delta', text: '...' } }
    if (payload.delta && typeof payload.delta === 'object') {
      const inner = payload.delta as Record<string, unknown>;
      if (typeof inner.text === 'string') {
        inner.text = restorer.push(inner.text) + (isDone ? restorer.flush() : '');
        changed = true;
      }
    }

    // Gemini SSE: candidates[0].content.parts[0].text
    if (Array.isArray(payload.candidates)) {
      for (const cand of payload.candidates) {
        const parts = (cand as { content?: { parts?: Array<Record<string, unknown>> } })?.content?.parts;
        if (Array.isArray(parts)) {
          for (const part of parts) {
            if (typeof part.text === 'string') {
              part.text = restorer.push(part.text) + (isDone ? restorer.flush() : '');
              changed = true;
            }
          }
        }
      }
    }

    return changed;
  };

  const processLine = (line: string): string => {
    // Vercel AI SDK Data Stream protocol v1: 0:"text chunk"
    if (line.startsWith('0:')) {
      try {
        const text = JSON.parse(line.slice(2));
        if (typeof text === 'string') {
          return '0:' + JSON.stringify(restorer.push(text));
        }
      } catch {
        return line;
      }
    }

    if (!line.startsWith('data:')) return line;
    const raw = line.slice(5).trim();
    if (raw === '[DONE]') {
      const tail = restorer.flush();
      if (tail.length > 0) {
        const flushedEvent = `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: tail } }] })}\n\n`;
        return flushedEvent + line;
      }
      return line;
    }

    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      if (restoreJsonPayload(parsed)) {
        return 'data: ' + JSON.stringify(parsed);
      }
    } catch {
      // Non-JSON data payload
      return 'data: ' + restorer.push(raw);
    }
    return line;
  };

  return {
    push(sseChunk: string): string {
      lineBuffer += sseChunk;
      const lines = lineBuffer.split('\n');
      lineBuffer = lines.pop() ?? '';
      return lines.map(processLine).join('\n') + (lines.length > 0 ? '\n' : '');
    },

    flush(): string {
      let out = '';
      if (lineBuffer.length > 0) {
        out += processLine(lineBuffer);
        lineBuffer = '';
      }
      const tail = restorer.flush();
      if (tail.length > 0) {
        out += `data: ${JSON.stringify({ type: 'text-delta', delta: tail })}\n\n`;
      }
      return out;
    },

    createByteTransformStream(): TransformStream<Uint8Array, Uint8Array> {
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();
      return new TransformStream<Uint8Array, Uint8Array>({
        transform: (chunk, controller) => {
          const text = decoder.decode(chunk, { stream: true });
          const out = this.push(text);
          if (out.length > 0) controller.enqueue(encoder.encode(out));
        },
        flush: (controller) => {
          const tail = this.push(decoder.decode()) + this.flush();
          if (tail.length > 0) controller.enqueue(encoder.encode(tail));
        },
      });
    },
  };
}
