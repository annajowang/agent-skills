#!/usr/bin/env node
/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Proof-of-Concept helper for the firebase-security-poc skill.
 *
 * Ports the `poc_context`, `install_dependencies` and `run_poc` tools of
 * https://github.com/gemini-cli-extensions/security (Apache-2.0) to a
 * dependency-free script, and adds Firebase-specific PoC types that run
 * against the local Firebase Emulator Suite with a `demo-*` project ID so
 * that no real Firebase project or production data is ever touched.
 *
 * Usage:
 *   node poc.mjs init --type <type> --location "<file:line>" [--root DIR]
 *        types: path_traversal | firestore_rules | storage_rules |
 *               rtdb_rules | http_endpoint | other
 *   node poc.mjs install --packages "<pkg@ver> ..." | --requirements FILE
 *                        | --script <pocDir/install_deps_x.sh>
 *   node poc.mjs run <pocFile> [--timeout 180]
 *   node poc.mjs clean
 *
 * A PoC communicates its verdict by printing a final line:
 *   POC_RESULT: VULNERABLE        (exploit succeeded)
 *   POC_RESULT: NOT_VULNERABLE    (exploit was blocked)
 * `run` parses this into the `verdict` field of its JSON output.
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const SECURITY_DIR_NAME = '.firebase-security';
export const POC_DIR_NAME = 'poc';
export const PATH_TRAVERSAL_CANARY = 'firebase_security_path_traversal_canary.txt';
export const DEMO_PROJECT_ID = 'demo-security-poc';
const FIREBASE_TOOLS = 'firebase-tools@latest';

const EMULATOR_TYPES = {
  firestore_rules: ['firestore'],
  storage_rules: ['storage'],
  rtdb_rules: ['database'],
};

function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function readText(p) {
  try {
    return fs.readFileSync(p, 'utf-8');
  } catch {
    return null;
  }
}

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch {
    return null;
  }
}

export function detectLanguage(root) {
  const files = fs.readdirSync(root);
  if (files.includes('package.json')) return 'node';
  if (files.includes('go.mod')) return 'go';
  if (files.includes('requirements.txt') || files.includes('pyproject.toml')) return 'python';
  if (files.includes('pubspec.yaml')) return 'node'; // Flutter: PoCs target the backend/rules, use Node.
  return 'node';
}

function pocDirFor(root) {
  return path.join(root, SECURITY_DIR_NAME, POC_DIR_NAME);
}

/** Locate the rules files the project's firebase.json points at. */
export function findRulesFiles(root) {
  const fj = readJson(path.join(root, 'firebase.json')) || {};
  const first = (v) => (Array.isArray(v) ? v[0] : v) || {};
  const pick = (declared, fallback) => {
    const p = declared || fallback;
    return p && exists(path.join(root, p)) ? path.join(root, p) : null;
  };
  return {
    firestore: pick(first(fj.firestore).rules, 'firestore.rules'),
    storage: pick(first(fj.storage).rules, 'storage.rules'),
    database: pick(first(fj.database).rules, 'database.rules.json'),
  };
}

/**
 * Writes a firebase.json inside the PoC dir so the emulator can be started
 * in isolation (demo project, fixed ports) without touching the user's config.
 */
function writeEmulatorConfig(root, pocDir, services) {
  const rules = findRulesFiles(root);
  // Rules are NOT referenced here: firebase-tools rejects paths outside the
  // PoC dir, and the PoC loads the app's live rules file itself via
  // initializeTestEnvironment({ firestore: { rules } }), so edits made by the
  // patcher are picked up on the next run without regenerating this file.
  const cfg = { emulators: { ui: { enabled: false }, singleProjectMode: true } };
  if (services.includes('firestore')) cfg.emulators.firestore = { port: 8181 };
  if (services.includes('storage')) cfg.emulators.storage = { port: 9199 };
  if (services.includes('database')) cfg.emulators.database = { port: 9009 };
  fs.writeFileSync(path.join(pocDir, 'firebase.json'), `${JSON.stringify(cfg, null, 2)}\n`);
  return { rules, emulatorPorts: { firestore: 8181, storage: 9199, database: 9009 } };
}

export function initPoc(root, { type = 'other', location = '', problem = '' } = {}) {
  const pocDir = pocDirFor(root);
  fs.mkdirSync(pocDir, { recursive: true });
  const ts = Date.now();
  const safeType = String(type).replace(/[^a-z_]/gi, '') || 'other';
  let language = detectLanguage(root);
  let ext = { node: 'mjs', python: 'py', go: 'go' }[language];
  const extra = [];
  let emulator = null;

  if (EMULATOR_TYPES[safeType]) {
    language = 'node';
    ext = 'mjs';
    const services = EMULATOR_TYPES[safeType];
    const info = writeEmulatorConfig(root, pocDir, services);
    emulator = { services, projectId: DEMO_PROJECT_ID, ...info };
    extra.push(
      '* Rules PoC: use `@firebase/rules-unit-testing` + the `firebase` JS SDK (install them with `poc.mjs install --packages "@firebase/rules-unit-testing firebase"`).',
      `* Call initializeTestEnvironment({ projectId: "${DEMO_PROJECT_ID}", ${services[0] === 'database' ? 'database' : services[0]}: { rules: fs.readFileSync(<rules file>, "utf8") } }). The emulator host/port env vars are injected by \`poc.mjs run\`.`,
      '* Seed data with testEnv.withSecurityRulesDisabled(), then attempt the attack as the attacker identity (testEnv.unauthenticatedContext() or testEnv.authenticatedContext("attacker", {...claims})).',
      '* Print `POC_RESULT: VULNERABLE` if the malicious read/write SUCCEEDS, otherwise `POC_RESULT: NOT_VULNERABLE`. Always call testEnv.cleanup().',
      '* See references/rules-poc.md for a complete template.',
    );
    if (!info.rules[services[0]]) extra.push(`* WARNING: no ${services[0]} rules file was found via firebase.json; pass the rules path explicitly in the PoC.`);
  } else if (safeType === 'path_traversal') {
    const canary = path.join(root, PATH_TRAVERSAL_CANARY);
    extra.push(
      `* A canary file is created at '${canary}' every time the PoC runs and removed afterwards.`,
      `* The PoC (running from '${pocDir}') must try to read the canary THROUGH the vulnerable code path (e.g. by calling the vulnerable function or HTTP endpoint with a "../" payload).`,
      '* Print `POC_RESULT: VULNERABLE` if the canary content is returned.',
    );
  } else if (safeType === 'http_endpoint') {
    extra.push(
      '* Target the LOCAL emulator or dev server only (e.g. http://127.0.0.1:5001/<demo-project>/<region>/<fn> or http://localhost:3000). Never send PoC traffic to a deployed/production URL.',
      `* To run against the Functions emulator, start it yourself in another terminal with \`npx -y ${FIREBASE_TOOLS} emulators:start --only functions --project ${DEMO_PROJECT_ID}\`, or ask the user to.`,
      '* Use the built-in global fetch (Node 18+); avoid extra dependencies.',
    );
  }
  extra.push('* Keep the PoC minimal, non-destructive and self-contained. Do not exfiltrate real data, call real third-party APIs, or modify files outside the PoC directory.');

  return {
    context: { problemStatement: problem, sourceCodeLocation: location, vulnerabilityType: safeType, language },
    pocDir,
    pocFileName: `poc_${safeType}_${ts}.${ext}`,
    emulator,
    extraInstructions: extra.join('\n'),
  };
}

function assertInsidePocDir(root, file) {
  const resolved = path.resolve(root, file);
  const safe = pocDirFor(root);
  if (!resolved.startsWith(safe + path.sep)) {
    throw Object.assign(new Error(`Security Error: only files inside '${safe}' may be executed (got '${resolved}').`), { security: true });
  }
  return resolved;
}

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, { encoding: 'utf-8', maxBuffer: 32 * 1024 * 1024, ...opts });
  return { exitCode: r.status, signal: r.signal, stdout: r.stdout || '', stderr: (r.stderr || '') + (r.error ? `\n${r.error.message}` : '') };
}

export function installDeps(root, { packages, requirements, script }) {
  const pocDir = pocDirFor(root);
  fs.mkdirSync(pocDir, { recursive: true });
  const env = { ...process.env, npm_config_cache: path.join(pocDir, '.npm_cache'), npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false' };
  if (packages) {
    if (!exists(path.join(pocDir, 'package.json'))) fs.writeFileSync(path.join(pocDir, 'package.json'), '{ "name": "firebase-security-poc", "private": true, "type": "module" }\n');
    const specs = String(packages).split(/\s+/).filter(Boolean);
    if (specs.some((s) => /[;&|`$<>]/.test(s))) throw new Error('Invalid package spec.');
    return run('npm', ['install', '--no-save', '--silent', ...specs], { cwd: pocDir, env });
  }
  if (requirements) {
    const venv = path.join(pocDir, '.venv');
    if (!exists(venv)) run('python3', ['-m', 'venv', venv], { cwd: pocDir });
    return run(path.join(venv, 'bin', 'python'), ['-m', 'pip', 'install', '-q', '-r', path.resolve(root, requirements)], { cwd: pocDir });
  }
  if (script) {
    const resolved = assertInsidePocDir(root, script);
    fs.chmodSync(resolved, 0o755);
    return run(resolved, [], { cwd: pocDir, env });
  }
  throw new Error('install requires --packages, --requirements or --script');
}

export function parseVerdict(stdout) {
  const m = [...stdout.matchAll(/POC_RESULT:\s*(VULNERABLE|NOT_VULNERABLE)/g)].pop();
  return m ? m[1] : 'INCONCLUSIVE';
}

/**
 * Decide which emulators a PoC needs: by filename (`poc_firestore_rules*`),
 * else by sniffing `@firebase/rules-unit-testing` + `initializeTestEnvironment`
 * config keys. Returns null for non-rules PoCs.
 */
export function detectEmulatorServices(base, file) {
  const m = base.match(/^poc_(firestore_rules|storage_rules|rtdb_rules)(?:[_.-]|$)/);
  if (m) return EMULATOR_TYPES[m[1]];
  let src = '';
  try {
    src = fs.readFileSync(file, 'utf-8');
  } catch {
    return null;
  }
  if (!/@firebase\/rules-unit-testing|initializeTestEnvironment/.test(src)) return null;
  const services = [];
  if (/\bfirestore\s*:/.test(src)) services.push('firestore');
  if (/\bstorage\s*:/.test(src)) services.push('storage');
  if (/\bdatabase\s*:/.test(src)) services.push('database');
  return services.length ? services : null;
}

export function runPoc(root, file, { timeoutSec = 180 } = {}) {
  const resolved = assertInsidePocDir(root, file);
  const pocDir = pocDirFor(root);
  const base = path.basename(resolved);
  const ext = path.extname(resolved).toLowerCase();
  const canary = path.join(root, PATH_TRAVERSAL_CANARY);
  const env = { ...process.env, npm_config_cache: path.join(pocDir, '.npm_cache'), GCLOUD_PROJECT: DEMO_PROJECT_ID, FIREBASE_SECURITY_POC: '1' };
  const timeout = Number(timeoutSec) * 1000;

  if (base.includes('path_traversal')) fs.writeFileSync(canary, 'FIREBASE_SECURITY_CANARY: path traversal confirmed\n');
  try {
    let cmd;
    let args;
    if (ext === '.py') {
      const venvPy = path.join(pocDir, '.venv', 'bin', 'python');
      cmd = exists(venvPy) ? venvPy : 'python3';
      args = [resolved];
    } else if (ext === '.go') {
      if (!exists(path.join(pocDir, 'go.mod'))) run('go', ['mod', 'init', 'poc'], { cwd: pocDir });
      run('go', ['mod', 'tidy'], { cwd: pocDir });
      cmd = 'go';
      args = ['run', resolved];
    } else if (ext === '.ts' || ext === '.mts') {
      cmd = 'npx';
      args = ['-y', 'tsx', resolved];
    } else {
      cmd = 'node';
      args = [resolved];
    }

    const services = detectEmulatorServices(base, resolved);
    let result;
    if (services) {
      const only = services.join(',');
      if (!exists(path.join(pocDir, 'firebase.json'))) writeEmulatorConfig(root, pocDir, services);
      const inner = [cmd, ...args].map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(' ');
      result = run('npx', ['-y', FIREBASE_TOOLS, 'emulators:exec', '--only', only, '--project', DEMO_PROJECT_ID, inner], { cwd: pocDir, env, timeout });
      if (/java/i.test(result.stderr) && /not found|Could not spawn|ENOENT/i.test(result.stderr)) {
        result.hint = 'The Firestore/Storage/RTDB emulators need a Java runtime (JDK 11+). Install Java, or fall back to a reasoning-only PoC and say so in the report.';
      }
      const debugLog = readText(path.join(pocDir, 'firestore-debug.log')) || '';
      if (/Security Manager is not supported/.test(result.stderr + result.stdout + debugLog)) {
        result.hint = 'The installed Java (24+) removed the Security Manager that the Firestore emulator still requests (JEP 486). Re-run with a JDK 11-21 first on PATH, e.g. JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 PATH=$JAVA_HOME/bin:$PATH node poc.mjs run ...';
      }
    } else {
      result = run(cmd, args, { cwd: pocDir, env, timeout });
    }
    if (result.signal === 'SIGTERM') result.timedOut = true;
    return { file: resolved, verdict: parseVerdict(result.stdout), ...result };
  } finally {
    if (exists(canary)) fs.unlinkSync(canary);
  }
}

function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const n = argv[i + 1];
      if (n === undefined || n.startsWith('--')) o[k] = true;
      else {
        o[k] = n;
        i++;
      }
    } else o._.push(a);
  }
  return o;
}

export function main(argv = process.argv.slice(2)) {
  const [cmd, ...rest] = argv;
  const o = parseArgs(rest);
  const root = path.resolve(o.root || process.cwd());
  const out = (x) => process.stdout.write(`${JSON.stringify(x, null, 2)}\n`);
  try {
    switch (cmd) {
      case 'init':
        out(initPoc(root, { type: o.type, location: o.location, problem: o.problem }));
        return 0;
      case 'install': {
        const r = installDeps(root, { packages: o.packages, requirements: o.requirements, script: o.script });
        out({ exitCode: r.exitCode, stdout: r.stdout.slice(-4000), stderr: r.stderr.slice(-4000) });
        return r.exitCode === 0 ? 0 : 1;
      }
      case 'run': {
        if (!o._[0]) throw new Error('Usage: run <pocFile>');
        const r = runPoc(root, o._[0], { timeoutSec: o.timeout || 180 });
        r.stdout = r.stdout.slice(-12000);
        r.stderr = r.stderr.slice(-6000);
        out(r);
        return 0;
      }
      case 'clean':
        fs.rmSync(pocDirFor(root), { recursive: true, force: true });
        out({ removed: pocDirFor(root) });
        return 0;
      default:
        process.stderr.write('Usage: poc.mjs <init|install|run|clean> ...\n');
        return 2;
    }
  } catch (e) {
    out({ error: e.message, securityError: !!e.security });
    return 1;
  }
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (invokedDirectly) process.exitCode = main();
