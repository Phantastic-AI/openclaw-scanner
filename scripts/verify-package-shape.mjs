#!/usr/bin/env node
/**
 * verify-package-shape.mjs — Pre-publish checks for openclaw-scanner
 *
 * Runs as `prepublishOnly` to ensure the package is well-formed before npm publish.
 * Also callable from CI: `node scripts/verify-package-shape.mjs`
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const errors = [];

function check(label, condition) {
  if (!condition) {
    errors.push(`FAIL: ${label}`);
    console.error(`  ✗ ${label}`);
  } else {
    console.log(`  ✓ ${label}`);
  }
}

console.log('Verifying package shape for openclaw-scanner...\n');

// 1. package.json checks
const pkgPath = join(root, 'package.json');
check('package.json exists', existsSync(pkgPath));

const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
check('name is "openclaw-scanner" (unscoped)', pkg.name === 'openclaw-scanner');
check('not marked private', pkg.private !== true);
check('version is semver-shaped', /^\d+\.\d+\.\d+/.test(pkg.version));
check('main points to index.mjs', pkg.main === 'index.mjs');
check('type is "module"', pkg.type === 'module');
check('license is MIT', pkg.license === 'MIT');
check('has repository url', !!pkg.repository?.url);
check('has files array', Array.isArray(pkg.files) && pkg.files.length > 0);
check('bin.openclaw-scand points to bin/openclaw-scand.mjs', pkg.bin?.['openclaw-scand'] === 'bin/openclaw-scand.mjs');
check(
  'openclaw.extensions includes "./index.mjs"',
  Array.isArray(pkg.openclaw?.extensions) && pkg.openclaw.extensions.includes('./index.mjs'),
);

// 2. Required files exist
const requiredFiles = [
  'index.mjs',
  'openclaw.plugin.json',
  'README.md',
  'LICENSE',
  'bin/openclaw-scand.mjs',
  'lib/policy.mjs',
  'lib/cache.mjs',
  'lib/gateway-model.mjs',
  'lib/text.mjs',
  'lib/antivirus.mjs',
  'lib/scan-daemon.mjs',
  'lib/scan-daemon-server.mjs',
  'lib/openclaw-scand-service.mjs',
  'lib/promptscanner-client.mjs',
  'lib/review-ledger-report.mjs',
];

for (const f of requiredFiles) {
  check(`${f} exists`, existsSync(join(root, f)));
}

// 3. openclaw.plugin.json checks
const pluginPath = join(root, 'openclaw.plugin.json');
if (existsSync(pluginPath)) {
  const plugin = JSON.parse(readFileSync(pluginPath, 'utf8'));
  check('plugin id is "openclaw-scanner"', plugin.id === 'openclaw-scanner');
  check('plugin version matches package version', plugin.version === pkg.version);
  check('plugin has configSchema', !!plugin.configSchema);
  check('plugin has version', !!plugin.version);
}

// 4. index.mjs is not empty
const indexStat = statSync(join(root, 'index.mjs'));
check('index.mjs is non-trivial (>1KB)', indexStat.size > 1024);

// 5. No private/internal path leaks in README
const readme = readFileSync(join(root, 'README.md'), 'utf8');
check('README has no /home/debian paths', !readme.includes('/home/debian/'));
check('README has no /home/hal paths', !readme.includes('/home/hal/'));

// 6. No .npmrc or secrets in files list
if (pkg.files) {
  check('files array excludes .npmrc', !pkg.files.includes('.npmrc'));
  check('files array excludes .env', !pkg.files.includes('.env'));
}

console.log('');
if (errors.length > 0) {
  console.error(`${errors.length} check(s) failed. Fix before publishing.`);
  process.exit(1);
} else {
  console.log('All checks passed. Ready to publish.');
}
