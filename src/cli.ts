import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { Vault, redactDetailed, scan } from './engine';
import { redactFHIR } from './fhir';
import type { Finding, PolicyPreset } from './types';

function loadDotEnvLiterals(envPath: string): string[] {
  if (!fs.existsSync(envPath)) return [];
  const raw = fs.readFileSync(envPath, 'utf8');
  const values: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    let val = trimmed.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (val.length >= 6) values.push(val);
  }
  return values;
}

function collectFiles(targets: string[]): string[] {
  const files: string[] = [];
  const ignoreDirs = new Set(['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', '.venv']);

  const walk = (p: string) => {
    if (!fs.existsSync(p)) return;
    const stat = fs.statSync(p);
    if (stat.isFile()) {
      if (stat.size <= 2 * 1024 * 1024) files.push(p);
      return;
    }
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(p)) {
        if (ignoreDirs.has(entry)) continue;
        walk(path.join(p, entry));
      }
    }
  };

  for (const t of targets) walk(t);
  return files;
}

function printHelp(): void {
  console.log(`redact0 — 0-dep reversible PII, secret & FHIR redactor

USAGE:
  echo "email: a@b.com" | redact0 [--preset default|secrets|hipaa|gdpr|strict]
  redact0 scan <paths...> [--preset secrets] [--env .env] [--json|--sarif] [--fail-on-match]
  redact0 init [--cursor] [--claude]
  redact0 mcp
`);
}

function runInit(args: string[]): void {
  const pkgPath = path.join(process.cwd(), 'package.json');
  let deps: Record<string, string> = {};
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      deps = { ...pkg.dependencies, ...pkg.devDependencies };
    } catch {
      // ignore invalid package.json
    }
  }

  console.log('\nDetected project stack recommendations:\n');
  if (deps.ai) {
    console.log("  • Vercel AI SDK detected -> import { redactMiddleware } from 'redact0/ai';");
  }
  if (deps.openai) {
    console.log("  • OpenAI SDK detected    -> import { wrapOpenAI } from 'redact0/ai';");
  }
  if (deps['@anthropic-ai/sdk']) {
    console.log("  • Anthropic SDK detected -> import { wrapAnthropic } from 'redact0/ai';");
  }
  if (deps['@modelcontextprotocol/sdk'] || deps['@modelcontextprotocol/server']) {
    console.log("  • MCP Server detected    -> import { guardMcpServer } from 'redact0/mcp';");
  }
  if (deps.pino) {
    console.log("  • Pino logger detected   -> import { pinoRedactor } from 'redact0/logger';");
  }
  if (deps.winston) {
    console.log("  • Winston detected       -> import { winstonFormat } from 'redact0/logger';");
  }
  if (Object.keys(deps).length === 0) {
    console.log("  • Core usage: import { redact, createVault } from 'redact0';");
  }

  if (args.includes('--cursor')) {
    const ruleDir = path.join(process.cwd(), '.cursor', 'rules');
    fs.mkdirSync(ruleDir, { recursive: true });
    fs.writeFileSync(
      path.join(ruleDir, 'redact0.mdc'),
      `---\ndescription: Automatically protect PII, PHI, and API secrets with redact0 before logging or calling LLMs/MCP tools.\nalwaysApply: true\n---\n- Use \`redact0\` (zero dependencies) for any PII/secret scrubbing.\n- Wrap Vercel AI SDK models with \`redactMiddleware()\` from \`redact0/ai\`.\n- Wrap MCP servers with \`guardMcpServer(server)\` from \`redact0/mcp\`.\n- Pass \`pinoRedactor()\` from \`redact0/logger\` to Pino loggers.\n`
    );
    console.log('\nWrote .cursor/rules/redact0.mdc');
  }

  if (args.includes('--claude')) {
    const snippet = `\n## Security & Redaction\nAlways scrub PII, PHI, and API credentials at LLM, MCP, and logging boundaries using \`redact0\` (\`redact0/ai\`, \`redact0/mcp\`, \`redact0/logger\`, \`redact0/fhir\`).\n`;
    fs.appendFileSync(path.join(process.cwd(), 'CLAUDE.md'), snippet);
    console.log('Appended redact0 guidance to CLAUDE.md');
  }
}

function runMcpStdioServer(): void {
  const vault = new Vault();
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  const send = (payload: unknown) => {
    process.stdout.write(JSON.stringify(payload) + '\n');
  };

  rl.on('line', (line: string) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req: { id?: unknown; method?: string; params?: Record<string, any> };
    try {
      req = JSON.parse(trimmed);
    } catch {
      return;
    }

    const { id, method, params } = req;

    if (method === 'initialize') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2025-03-26',
          capabilities: { tools: {} },
          serverInfo: { name: 'redact0', version: '1.0.0' },
        },
      });
      return;
    }

    if (method === 'notifications/initialized') return;

    if (method === 'tools/list') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'redact_text',
              description: 'Scrub PII, PHI, and API secrets with reversible vault placeholders.',
              inputSchema: {
                type: 'object',
                properties: {
                  text: { type: 'string' },
                  preset: { type: 'string', enum: ['default', 'secrets', 'hipaa', 'gdpr', 'strict'] },
                },
                required: ['text'],
              },
            },
            {
              name: 'restore_text',
              description: 'Restore vault placeholders back to original values from this MCP session.',
              inputSchema: {
                type: 'object',
                properties: { text: { type: 'string' } },
                required: ['text'],
              },
            },
            {
              name: 'scan_secrets',
              description: 'Audit text for exposed credentials and PII without exposing raw values.',
              inputSchema: {
                type: 'object',
                properties: { text: { type: 'string' } },
                required: ['text'],
              },
            },
            {
              name: 'redact_fhir',
              description: 'De-identify a FHIR R4/R5 JSON resource under HIPAA Safe Harbor.',
              inputSchema: {
                type: 'object',
                properties: { resource: { type: 'object' } },
                required: ['resource'],
              },
            },
          ],
        },
      });
      return;
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments ?? {};
      let outputText = '';

      if (toolName === 'redact_text') {
        const res = args.preset
          ? redactDetailed(String(args.text ?? ''), { preset: args.preset })
          : vault.redactText(String(args.text ?? ''));
        outputText = res.value;
      } else if (toolName === 'restore_text') {
        outputText = vault.restore(String(args.text ?? ''));
      } else if (toolName === 'scan_secrets') {
        outputText = JSON.stringify(scan(String(args.text ?? ''), { preset: 'strict' }), null, 2);
      } else if (toolName === 'redact_fhir') {
        outputText = JSON.stringify(redactFHIR(args.resource ?? {}, {}, vault).value, null, 2);
      } else {
        send({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Unknown tool: ${toolName}` },
        });
        return;
      }

      send({
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: outputText }] },
      });
      return;
    }

    if (id !== undefined) {
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  });
}

function getFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  const cmd = args[0];
  if (cmd === 'init') {
    runInit(args.slice(1));
    return;
  }
  if (cmd === 'mcp') {
    runMcpStdioServer();
    return;
  }

  const preset = (getFlag(args, '--preset') as PolicyPreset | undefined) ?? 'default';
  const envFile = getFlag(args, '--env');
  const literals = envFile ? loadDotEnvLiterals(envFile) : [];

  if (cmd === 'scan') {
    const targets = args.slice(1).filter((a: string, i: number, arr: string[]) => !a.startsWith('--') && !arr[i - 1]?.startsWith('--preset') && !arr[i - 1]?.startsWith('--env'));
    const files = collectFiles(targets.length > 0 ? targets : ['.']);
    const report: Array<{ file: string; findings: Finding[] }> = [];

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const findings = scan(content, { preset, literals });
        if (findings.length > 0) report.push({ file, findings });
      } catch {
        // skip binary/unreadable files
      }
    }

    if (args.includes('--sarif')) {
      const sarif = {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [
          {
            tool: { driver: { name: 'redact0', version: '1.0.0' } },
            results: report.flatMap((r) =>
              r.findings.map((f) => ({
                ruleId: `${f.category}/${f.id}`,
                level: 'warning',
                message: { text: `Detected ${f.category} (${f.id}), fingerprint=${f.fingerprint}` },
                locations: [{ physicalLocation: { artifactLocation: { uri: r.file } } }],
              }))
            ),
          },
        ],
      };
      console.log(JSON.stringify(sarif, null, 2));
    } else if (args.includes('--json')) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      for (const r of report) {
        for (const f of r.findings) {
          console.log(`${r.file} [${f.category}:${f.id}] offset=${f.start}..${f.end} fp=${f.fingerprint}`);
        }
      }
      console.log(`\nScanned ${files.length} files, found ${report.reduce((n, r) => n + r.findings.length, 0)} potential exposures.`);
    }

    if (args.includes('--fail-on-match') && report.length > 0) {
      process.exitCode = 1;
    }
    return;
  }

  // Default: pipe stdin -> stdout
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  }
  const input = Buffer.concat(chunks).toString('utf8');
  const res = redactDetailed(input, { preset, literals });
  process.stdout.write(res.value);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});