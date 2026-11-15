# AGENTS.md — redact0

- This repository builds **redact0**, published identically on npm (`redact0`) and PyPI (`redact0`).
- **Hard invariant**: `package.json` `"dependencies"` and `python/pyproject.toml` `dependencies` MUST remain empty (`{}` / `[]`).
- Core TypeScript bundle (`dist/index.mjs` gzipped) MUST stay strictly under 30 KB (`npm run check:size`).
- Run `npm run typecheck && npm run build && npm test && npm run check:size` for TypeScript verification.
- Run `PYTHONPATH=python/src pytest python/tests` for Python verification.
