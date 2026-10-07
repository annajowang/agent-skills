/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Run: node --test skills/firebase-security-poc/scripts/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { initPoc, runPoc, parseVerdict, PATH_TRAVERSAL_CANARY } from './poc.mjs';

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fbpoc-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('parseVerdict takes the last POC_RESULT line', () => {
  assert.equal(parseVerdict('x\nPOC_RESULT: VULNERABLE\n'), 'VULNERABLE');
  assert.equal(parseVerdict('POC_RESULT: VULNERABLE\nPOC_RESULT: NOT_VULNERABLE'), 'NOT_VULNERABLE');
  assert.equal(parseVerdict('nothing'), 'INCONCLUSIVE');
});

test('initPoc for rules writes an isolated emulator config on a demo project', () => {
  const dir = tmpProject({
    'package.json': '{}',
    'firebase.json': JSON.stringify({ firestore: { rules: 'firestore.rules' } }),
    'firestore.rules': "rules_version = '2';",
  });
  const r = initPoc(dir, { type: 'firestore_rules', location: 'firestore.rules:3' });
  assert.match(r.pocFileName, /^poc_firestore_rules_\d+\.mjs$/);
  assert.equal(r.emulator.projectId, 'demo-security-poc');
  const cfg = JSON.parse(fs.readFileSync(path.join(r.pocDir, 'firebase.json'), 'utf-8'));
  assert.equal(cfg.emulators.firestore.port, 8181);
  assert.equal(cfg.firestore, undefined);
  assert.equal(r.emulator.rules.firestore, path.join(dir, 'firestore.rules'));
});

test('runPoc refuses files outside the PoC dir', () => {
  const dir = tmpProject({ 'package.json': '{}', 'evil.mjs': 'console.log(1)' });
  assert.throws(() => runPoc(dir, 'evil.mjs'), /Security Error/);
});

test('runPoc runs node PoCs, creates and removes the traversal canary', () => {
  const dir = tmpProject({ 'package.json': '{}' });
  const r = initPoc(dir, { type: 'path_traversal' });
  const file = path.join(r.pocDir, r.pocFileName);
  fs.writeFileSync(file, `import fs from 'node:fs';\nconst t = fs.readFileSync('../../${PATH_TRAVERSAL_CANARY}', 'utf8');\nconsole.log(t);\nconsole.log('POC_RESULT: ' + (t.includes('CANARY') ? 'VULNERABLE' : 'NOT_VULNERABLE'));\n`);
  const out = runPoc(dir, file);
  assert.equal(out.verdict, 'VULNERABLE');
  assert.equal(fs.existsSync(path.join(dir, PATH_TRAVERSAL_CANARY)), false);
});
