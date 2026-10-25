# Read-only deployment evidence collector

## Intent

Preserve useful, credential-safe evidence from an already-authorized Ludus run.
Prevent lost multiline diagnostic reports, task-heading-as-success claims, and
collection versions attributed to the wrong module installation or process.

## Approach

The user selected a standalone collector instead of promoting the ignored
deployment utility. The latter also uploads, deploys, and manages run state;
bringing it into this task would unnecessarily expand authority and scope.
Documentation alone would not prevent the repeated parsing/persistence defects.

## Proposed interface and boundaries

- A Python standard-library CLI under `scripts/`, with parser helpers separated
  from argument handling where useful. No new runtime dependencies.
- Input: raw Ansible default-callback text through stdin, a Ludus JSON status
  snapshot, explicit expected range/deployment identity, a reviewed allowlist of
  hosts and task names, and an output directory.
- No network, SSH, Ludus invocation, deployment, guest probe, or secret discovery.
  Authorized callers supply input; this tool does not create authorization.
- Raw log content is processed in memory and never written or echoed, including
  exceptions and malformed-input diagnostics. Input/buffer sizes are bounded.
- The reviewed allowlist is a trusted local contract, not generated automatically
  from untrusted log text. Arbitrary task names, messages and result values are
  excluded from evidence. Unknown/malformed content is reported with fixed codes.
- Initially recognize the existing collector role's fixed Helm and shared/
  Kubernetes input diagnostic report schemas. Reject unknown keys, invalid types,
  unsafe metadata and unrecognized report shapes rather than copying them.

## Evidence contract

- Record expected and observed deployment identity separately. A matching status
  snapshot supports status attribution; it does not independently prove that an
  arbitrary supplied log stream belongs to that deployment. State that limitation.
- Preserve allowlisted host/task outcomes as observed: ok, changed, skipped,
  failed, unreachable, or unknown. A heading without a result remains unknown.
  Repeated task names must not overwrite earlier occurrences.
- Decode multiline callback JSON and save the actual validated diagnostic object,
  not just a schema-validation receipt. Preserve multiple report occurrences.
- Save bounded recap counters and terminal status separately; missing outcomes,
  contradictory evidence, truncation, or identity mismatches cannot become success.
- Write only sanitized JSON artifacts, using restrictive permissions and safe
  output-path handling. Read them back and verify equality before reporting
  successful capture. Do not overwrite an existing capture silently.
- Distinguish capture success from deployment success and from readiness or
  ingestion verification. Missing optional diagnostics after a successful run is
  not itself a failure.

## Existing guidance updates

Extend `docs/instructions/live-debugging.md`, keeping `/live` as its thin entrypoint:

1. Document collector usage and status/log attribution limits, task-outcome rules,
   actual report persistence, and explicit remote role-byte hash verification when
   authorized transport is available. Mark unavailable evidence instead of guessing.
2. Add module-provenance checks: resolved module path/realpath, same-root manifest,
   namespace/name/version, source hash, execution context and timestamp. Distinguish
   current/post-failure loader snapshots from the failed worker's executed payload.
3. Add pinned dependency diagnosis: compare the exact schema, merged defaults,
   vendor examples and activation/template conditions together before proposing a
   correction. Static compatibility is not live readiness evidence.

No new agent, skill, model routing, global config, permission change, or approval
gate. Do not alter production roles or the completed dev1 deployment.

## Verification

Use test-first checks of the real parser and CLI with bounded callback text:
multiline reports, omitted/malformed results, skipped tasks, repeated headings,
schema rejection, identity mismatch, truncation and output collisions. Feed
credential canaries through the production parser and ensure no artifact/stdout/
stderr contains them. These are direct tests of a local text-processing tool,
not simulations of Ansible roles or evidence of deployment behavior.

Reuse existing permitted sanitized evidence where applicable. Run the collector's
test suite and Python syntax checks, inspect the final diff and documentation
commands, and report unsupported callback formats and attribution limits. No live
deployment or guest access is authorized or necessary for this implementation.

## Builder decisions

Exact flag names, JSON layout, conservative resource limits and test organization
are implementation choices. Keep them small and document them. Support the
observed default callback format first; other callbacks are explicitly unsupported.
All changes remain uncommitted unless separately requested.
