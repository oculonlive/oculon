// Copies non-TypeScript web files (pages and images) into dist after tsc.
import { cpSync, mkdirSync } from 'node:fs';
mkdirSync('dist/web', { recursive: true });
cpSync('src/web', 'dist/web', { recursive: true, filter: (src) => !src.endsWith('.ts') });
console.log('copied src/web pages and assets -> dist/web');
