---
name: firebase-security-poc
description: >-
  Builds and runs a safe, local Proof-of-Concept (PoC) that demonstrates whether a reported vulnerability in a Firebase app is actually exploitable - including Firestore/Storage/Realtime Database rules exploits against the Firebase Emulator Suite, unauthenticated Cloud Functions/API calls, path traversal and injection. Use when the user asks to prove, reproduce, demonstrate, exploit or verify a security finding, or picks "Generate a Proof-of-Concept" after a firebase-security-review. Don't use against deployed/production URLs or real Firebase projects.
metadata:
  author: Google LLC
  category: CloudSecurity
---

# Firebase Security PoC

Turn a finding into evidence: a minimal script that prints
`POC_RESULT: VULNERABLE` if the exploit works and `POC_RESULT: NOT_VULNERABLE`
if it is blocked. The same PoC is re-run after the patch to prove the fix (see
`firebase-security-patcher`). Ports the `poc` and `dependency-manager` skills of
the
[Gemini CLI Security extension](https://github.com/gemini-cli-extensions/security).

## Safety rules (non-negotiable)

- Local only: Firebase Emulator Suite with project ID `demo-security-poc`
  (`demo-*` projects can never reach real Firebase resources), a local dev
  server, or a direct function call. **Never** target a deployed URL or a real
  project, even if the user asks - explain why and offer the emulator instead.
- Non-destructive, no real data, no real third-party API calls, no network
  exfiltration. Write only inside `.firebase-security/poc/`.
- If several findings are selected, ask which one to PoC first (one PoC per
  finding).

## Helper script

Resolve `<SKILL_DIR>` to the directory containing this `SKILL.md`. Run from the
project root:

| Command                                                                                              | Purpose                                                                                                                 |
| ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `node <SKILL_DIR>/scripts/poc.mjs init --type <type> --location "<file:line>" --problem "<summary>"` | Creates `.firebase-security/poc/`, returns `pocDir`, `pocFileName`, `language`, emulator config and `extraInstructions` |
| `node <SKILL_DIR>/scripts/poc.mjs install --packages "<pkg@ver> ..."`                                | Installs PoC-only npm deps into the PoC dir (isolated cache, never touches the app's `package.json`)                    |
| `node <SKILL_DIR>/scripts/poc.mjs install --requirements <file>`                                     | Python deps into a PoC venv                                                                                             |
| `node <SKILL_DIR>/scripts/poc.mjs run <pocDir>/<pocFileName> [--timeout 180]`                        | Runs the PoC (rules types are wrapped in `firebase emulators:exec`), returns `verdict`, stdout, stderr                  |
| `node <SKILL_DIR>/scripts/poc.mjs clean`                                                             | Deletes the PoC dir                                                                                                     |

`--type` values: `firestore_rules`, `storage_rules`, `rtdb_rules`,
`http_endpoint`, `path_traversal`, `other`. Pick the closest; infer it from the
finding.

## Workflow

1. **Locate the vulnerable code.** Get the file and line from the report
   (`.firebase-security/SECURITY_REPORT.md`) or the user. If you only have a
   description, search the codebase first.
1. **Init.** Run `poc.mjs init` and keep the returned JSON. Follow every line of
   `extraInstructions`.
1. **Dependencies (dependency-manager).**
   - Read the nearest manifest (`package.json`, `requirements.txt`, `go.mod`,
     `pom.xml`/`build.gradle`) walking up from the vulnerable file and reuse the
     **same versions** the app uses for any library you import.
   - Install with `poc.mjs install`. For rules PoCs:
     `--packages "@firebase/rules-unit-testing firebase"`.
   - Prefer importing the app's own vulnerable function directly (relative
     import from the PoC dir) over re-implementing it - that proves the real
     code is affected.
1. **Write the PoC** at `<pocDir>/<pocFileName>`:
   - Rules: see [references/rules-poc.md](references/rules-poc.md).
   - HTTP / Functions / API routes: see
     [references/endpoint-poc.md](references/endpoint-poc.md).
   - Path traversal: read the canary file named in `extraInstructions` through
     the vulnerable code path.
   - Injection/XSS/SSRF in a pure function: import the function, call it with a
     payload, assert on the dangerous output (e.g. unescaped `<script>`, a
     request to `http://169.254.169.254`, a shell metacharacter reaching
     `exec`). Stub the sink (e.g. monkey-patch `fetch` or `child_process.exec`)
     so nothing dangerous actually executes.
   - End with exactly one `POC_RESULT:` line.
1. **Run** with `poc.mjs run`. Interpret `verdict`:
   - `VULNERABLE` - confirmed. Show the user the evidence (the relevant stdout
     lines) in plain language: "An anonymous user read `/users/alice`."
   - `NOT_VULNERABLE` - the finding may be a false positive, or the PoC is
     wrong. Re-check the PoC logic once; if still blocked, tell the user and
     offer to allowlist the finding (see `firebase-security-review`).
   - `INCONCLUSIVE` - read stderr. Common causes: missing Java for emulators
     (`hint` field), missing deps, wrong import path. Fix and retry at most
     twice, then report the blocker instead of looping.
1. **Hand off.** If vulnerable, ask whether to patch now. If yes, invoke
   `firebase-security-patcher` and pass it the PoC path so it can verify the
   fix.

## When a runnable PoC is impossible

If tooling is missing (no Java for emulators, no network for `npx`) or the issue
is configuration-only (e.g. a secret committed to git), write a **reasoning
PoC** instead: the exact attacker steps (e.g. the `curl` command or SDK call an
attacker would make) and the expected result, clearly labelled "not executed".
Never claim a PoC ran when it did not.
