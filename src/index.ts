#!/usr/bin/env bun



import { runCli } from './cli/index.ts';

runCli(process.argv.slice(2)).catch((err) => {
  console.error(`\n❌ Fatal Error: ${err.message}\n`);
  process.exit(1);
});
