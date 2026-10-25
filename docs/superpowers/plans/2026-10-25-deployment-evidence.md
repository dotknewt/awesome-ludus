# Deployment Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture safe deployment evidence without performing remote operations.

**Architecture:** A standard-library Python CLI consumes default-callback text
from stdin and local status/allowlist JSON. A parser and fixed diagnostic schemas
produce sanitized JSON; the CLI persists it privately and verifies readback.
Existing deployment instructions remain the workflow entrypoint.

**Tech Stack:** Python 3 standard library, unittest, Markdown.

**Spec:** `docs/superpowers/specs/2026-10-25-deployment-evidence-design.md`

## Global Constraints

- No network, SSH, Ludus invocation, deployment, guest probe, or secret discovery.
- Raw log content is processed in memory and never written or echoed.
- The reviewed allowlist is a trusted local contract.
- All changes remain uncommitted unless separately requested.
- Do not change Ansible roles, global config, agents, skills, or `/live` authority.
- Tests exercise the actual local parser/CLI; they do not simulate role behavior.

## Review Focus

- Duplicate JSON keys/nonfinite numbers and malformed multiline records must not
  create apparently valid safe reports (Task 1).
- Repeated task names, delegated hosts and headings without outcomes must not
  overwrite evidence or become success (Task 1).
- Untrusted message/task/host strings and canary-bearing errors must not escape
  through stdout, stderr, exception text or persisted artifacts (Tasks 1–2).
- Mismatched deployment IDs and truncated input preserve uncertainty, rather than
  silently combining status from one run with logs from another (Tasks 1–2).
- Existing output directories, symlinks and partial writes must not overwrite
  unrelated files or leave an apparently verified capture (Task 2).

### Task 1: Parser and fixed report profiles

**Files:** create `scripts/deployment_evidence.py`,
`scripts/deployment_evidence_profiles.py`,
`tests/test_deployment_evidence.py`.

**Interfaces:**
- `collect_evidence(stream, status: dict, allowlist: dict, *, range_id: str,
  deployment: str) -> dict` consumes a text stream and produces only safe evidence.
- Allowlist JSON: exactly `{"hosts": ["reviewed-host"], "tasks": ["reviewed-task"]}`;
  task entries are exact text inside `TASK [...]`, including role prefix.
- Fixed report profiles recognize existing Helm and shared/Kubernetes input
  publication task names and validate against the actual role action output
  contracts. Helpers return safe objects or fixed rejection codes, never raw data.
- Evidence contains expected/observed run identity, status, explicit attribution
  limit, ordered task occurrences/results, recap counters, validated reports, and
  fixed issues. Do not infer executed-module provenance from loader snapshots.

- [ ] Write direct parser/profile tests first: multiline JSON report survives;
  missing result remains unknown; skipped remains skipped; repeated names remain
  separate; arbitrary values/unknown keys rejected; all three existing profiles
  checked against their current production source contracts.
- [ ] Add adversarial cases from Review Focus: duplicate keys, nonfinite values,
  unsupported callback forms, delegated host identity, truncated/oversized input,
  contradictory repeated outcomes, mismatched run IDs and canaries in every raw
  text position. No mocked role runtime or fake deployment conclusions.
- [ ] Run the focused test file through the command specialist and save failing
  output before production implementation. Expected: absent implementation or
  unmet contract, not unrelated dependency failures.
- [ ] Implement bounded parsing, strict profile validation and conservative
  outcome extraction. Preserve raw text only transiently in memory. Reject
  unknown names except fixed counters/codes; bounds are constants, not switches.
- [ ] Run focused tests green and save commands, exits and hashes for reuse.

### Task 2: CLI and safe persistence

**Files:** create `scripts/collect_deployment_evidence.py`; extend same test file.

**Interface:**
`python3 scripts/collect_deployment_evidence.py --range RANGE --deployment UTC_ID
--status STATUS_JSON --allowlist ALLOWLIST_JSON --output NEW_DIRECTORY`
reads logs from stdin. `--help` explains supported format and trust boundaries.

- [ ] Write CLI tests using subprocess against the real entrypoint: valid capture,
  malformed inputs, bounded input, private file modes, existing-output refusal,
  symlink refusal, and credential-canary non-disclosure in artifacts/stdout/stderr.
- [ ] Run red before CLI implementation; save raw output in ignored evidence.
- [ ] Implement fixed safe errors, bounded local input reads and exclusive private
  output creation. Write `evidence.json`, read back and compare before confirming
  capture. Reject symlink components and existing destinations; avoid destructive
  cleanup. On failure, no verified-success receipt.
- [ ] Exit0 means valid complete capture, not successful deployment. Exit3 means
  a safely persisted incomplete capture; exit2 means invalid input/output error.
  A captured failed deployment is not a collector process error. Print fixed
  capture status only, not unvalidated paths or argument values.
- [ ] Run focused tests green; worker checks only its new tool/test scope.

### Task 3: Existing workflow guidance and final review

**Files:** modify `docs/instructions/live-debugging.md` (parent-owned).

- [ ] Document CLI usage, reviewed allowlists, private local status input, raw-log
  pipe rather than disk capture, exact run attribution limits, and exit semantics.
- [ ] Add remote content hash evidence guidance without implying local paths are
  remote paths or granting SSH authority; carry missing evidence explicitly.
- [ ] Add same-root module provenance checklist and distinguish loader snapshots.
- [ ] Add exact pinned schema/defaults/vendor-example/activation-condition checks.
  Keep schema validation/security intact; static evidence is not runtime proof.
- [ ] Parent reads implementation/diff and reconciles docs with actual CLI.
  Independent reviewer checks disclosure, attribution and persistence boundaries.
- [ ] One command owner runs the entire new tool test suite after reconciliation,
  Python syntax and scoped diff checks. Reuse still-valid prior artifacts; no
  deployment/guest probe. Record exact commands, exits, hashes and residual limits.
- [ ] Report usage and delivered scope. Do not commit or push.
