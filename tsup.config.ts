import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      stream: 'src/stream.ts',
      fhir: 'src/fhir.ts',
      ai: 'src/ai.ts',
      mcp: 'src/mcp.ts',
      logger: 'src/logger.ts',
    },
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    minify: true,
    treeshake: true,
    splitting: false,
    outExtension({ format }) {
      return { js: format === 'esm' ? '.mjs' : '.cjs' };
    },
  },
  {
    entry: {
      cli: 'src/cli.ts',
    },
    format: ['cjs'],
    dts: false,
    minify: true,
    treeshake: true,
    banner: {
      js: '#!/usr/bin/env node',
    },
    outExtension() {
      return { js: '.cjs' };
    },
  },
]);
