import { Vault } from './engine';
import type { RedactOptions } from './types';

export interface McpGuardOptions extends RedactOptions {
  /** Shared vault for rehydrating tokens across MCP tool calls and LLM prompts. */
  vault?: Vault;
  /**
   * 'output' (default): scrubs tool responses before returning to LLM.
   * 'input': scrubs arguments before invoking tool.
   * 'both': scrubs inputs and outputs.
   */
  direction?: 'output' | 'input' | 'both';
  /**
   * When true (default), restores vault tokens inside incoming tool arguments
   * so trusted local tools execute with real values while outputs stay scrubbed.
   */
  rehydrateToolInputs?: boolean;
  /** Optional hook invoked when sensitive data is scrubbed from tool outputs/inputs. */
  onRedaction?: (info: { toolName: string; direction: 'input' | 'output'; count: number }) => void;
}

/**
 * Zero-dependency guard for `@modelcontextprotocol/sdk` v1 (`server.tool` & `server.registerTool`)
 * and `@modelcontextprotocol/server` v2 (`server.registerTool`).
 */
export function guardMcpServer<T extends Record<string, any>>(
  server: T,
  options: McpGuardOptions = {}
): T {
  const vault = options.vault ?? new Vault(options);
  const direction = options.direction ?? 'output';
  const rehydrateInputs = options.rehydrateToolInputs ?? true;

  const wrapToolHandler = (toolName: string, handler: (...args: any[]) => Promise<any> | any) => {
    return async (...callArgs: any[]) => {
      const nextArgs = [...callArgs];
      if (nextArgs.length > 0 && nextArgs[0] && typeof nextArgs[0] === 'object') {
        if (rehydrateInputs && direction !== 'input') {
          nextArgs[0] = vault.restoreObject(nextArgs[0]);
        } else if (direction === 'input' || direction === 'both') {
          const res = vault.redactObject(nextArgs[0]);
          nextArgs[0] = res.value;
          if (res.count > 0) {
            options.onRedaction?.({ toolName, direction: 'input', count: res.count });
          }
        }
      }

      const result = await handler(...nextArgs);
      if (!result || typeof result !== 'object') return result;
      if (direction === 'input') return result;

      const out = { ...result };
      let totalCount = 0;

      if (Array.isArray(out.content)) {
        out.content = out.content.map((item: unknown) => {
          if (!item || typeof item !== 'object') return item;
          const part = { ...(item as Record<string, unknown>) };
          if (part.type === 'text' && typeof part.text === 'string') {
            const r = vault.redactText(part.text);
            totalCount += r.count;
            part.text = r.value;
          } else {
            const r = vault.redactObject(part);
            totalCount += r.count;
            return r.value;
          }
          return part;
        });
      }

      if (out.structuredContent !== undefined) {
        const r = vault.redactObject(out.structuredContent);
        totalCount += r.count;
        out.structuredContent = r.value;
      }

      if (totalCount > 0) {
        options.onRedaction?.({ toolName, direction: 'output', count: totalCount });
      }
      return out;
    };
  };

  if (typeof server.registerTool === 'function') {
    const origRegisterTool = server.registerTool.bind(server);
    (server as Record<string, any>).registerTool = (name: string, config: unknown, cb: any) => {
      if (typeof cb === 'function') {
        return origRegisterTool(name, config, wrapToolHandler(name, cb));
      }
      return origRegisterTool(name, config, cb);
    };
  }

  if (typeof server.tool === 'function') {
    const origTool = server.tool.bind(server);
    (server as Record<string, any>).tool = (name: string, ...args: any[]) => {
      const lastIdx = args.length - 1;
      if (lastIdx >= 0 && typeof args[lastIdx] === 'function') {
        const nextArgs = [...args];
        nextArgs[lastIdx] = wrapToolHandler(name, args[lastIdx]);
        return origTool(name, ...nextArgs);
      }
      return origTool(name, ...args);
    };
  }

  if (typeof server.registerResource === 'function') {
    const origRegisterResource = server.registerResource.bind(server);
    (server as Record<string, any>).registerResource = (...args: any[]) => {
      const lastIdx = args.length - 1;
      if (lastIdx >= 0 && typeof args[lastIdx] === 'function') {
        const origRead = args[lastIdx];
        const nextArgs = [...args];
        nextArgs[lastIdx] = async (...readArgs: any[]) => {
          const res = await origRead(...readArgs);
          return vault.redactObject(res).value;
        };
        return origRegisterResource(...nextArgs);
      }
      return origRegisterResource(...args);
    };
  }

  return server;
}
