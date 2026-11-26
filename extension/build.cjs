#!/usr/bin/env node
// Zips the extension into extension/dist/oculon-shield-<version>.zip (no dependencies).
// Leaves out dist/, the README and this script. Windows zips through PowerShell (.NET ZipFile; Compress-Archive in PowerShell 5.1 writes backslash entry names), other systems use `zip`.
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = __dirname;
const { version } = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
const dist = path.join(root, 'dist');
const out = path.join(dist, `oculon-shield-${version}.zip`);
const EXCLUDE = new Set(['dist', 'README.md', 'build.cjs']);

fs.mkdirSync(dist, { recursive: true });
fs.rmSync(out, { force: true });

// Copy the files to a staging folder first so the zip holds manifest.json at its root.
const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'oculon-shield-'));
for (const name of fs.readdirSync(root)) {
  if (EXCLUDE.has(name) || name.startsWith('.')) continue;
  fs.cpSync(path.join(root, name), path.join(stage, name), { recursive: true });
}

try {
  if (process.platform === 'win32') {
    const q = (p) => `'${p.replace(/'/g, "''")}'`;
    // Compress-Archive in Windows PowerShell 5.1 writes "content\banner.js" style entry names, which break on
    // other unzip tools, so each file is added with a forward-slash name.
    const files = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else files.push([p, path.relative(stage, p).split(path.sep).join('/')]);
      }
    };
    walk(stage);
    const adds = files.map(([p, name]) => `[void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, ${q(p)}, ${q(name)}, 'Optimal')`).join('; ');
    const cmd = `Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem; $z = [IO.Compression.ZipFile]::Open(${q(out)}, 'Create'); try { ${adds} } finally { $z.Dispose() }`;
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], { stdio: 'inherit' });
  } else {
    execFileSync('zip', ['-r', '-q', out, '.'], { cwd: stage, stdio: 'inherit' });
  }
} finally {
  fs.rmSync(stage, { recursive: true, force: true });
}

console.log(`${path.relative(process.cwd(), out)} (${fs.statSync(out).size} bytes)`);
