#!/usr/bin/env node
/**
 * `oculon` binary. node:sqlite still prints an ExperimentalWarning on some Node versions; it is filtered
 * here (other warnings still show) before the real CLI is loaded with a dynamic import.
 */
process.removeAllListeners('warning');
process.on('warning', (w) => {
  if (w.name !== 'ExperimentalWarning') console.warn(w);
});

const { main } = await import('./cli/main.js');
const code = await main();
if (code !== 0) process.exitCode = code;
