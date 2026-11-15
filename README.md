# redact0

Zero-runtime-dependency reversible PII, secret, FHIR Safe Harbor and streaming redaction for JavaScript/TypeScript and Python.

> Security note: this package is a best-effort detector/redactor, not a compliance certification or a substitute for a privacy/security review. Validate it against your own data and regulatory requirements before production use.

## Requirements

- Node.js 18+ for the npm package
- Python 3.10+ for the PyPI package

## Install

```bash
npm install redact0
```

```bash
python -m pip install redact0
```

## JavaScript / TypeScript quick start

```ts
import { createVault, redact } from 'redact0';

const safe = redact({
  email: 'alice@example.com',
  message: 'Contact alice@example.com',
});

const vault = createVault();
const scrubbed = vault.redact('Send the report to alice@example.com').value;
const restored = vault.restore(scrubbed);
```

## Python quick start

```python
from redact0 import Vault, redact

safe = redact({"email": "alice@example.com"})
vault = Vault()
scrubbed = vault.redact("Contact alice@example.com").value
restored = vault.restore(scrubbed)
```

## Build and verify from this repository

```bash
npm install
npm run typecheck
npm run build
npm test
npm run check:size
```

Python checks (from the repository root):

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ./python
python -m pip install pytest
python -m pytest python/tests
```

The Python package itself declares no runtime dependencies. `pytest` is only needed to run its tests.

## CLI

After building the npm package:

```bash
echo "email: alice@example.com" | node dist/cli.cjs
npx redact0 init
npx redact0 scan . --preset secrets
npx redact0 mcp
```

For Python, after installation:

```bash
echo "email: alice@example.com" | redact0
```

## Exports

The npm package defines these subpath exports:

- `redact0/stream`
- `redact0/fhir`
- `redact0/ai`
- `redact0/mcp`
- `redact0/logger`

The Python package includes `redact0.compat.llm_guard` for compatibility helpers.

## Project layout

- `src/`: TypeScript implementation and adapters
- `tests/`: TypeScript tests
- `python/src/redact0/`: Python implementation
- `python/tests/`: Python tests
- `llms.txt`, `llms-full.txt`, `context7.json`, `AGENTS.md`: AI-agent and documentation discovery resources

## License

MIT. See [LICENSE](LICENSE).
