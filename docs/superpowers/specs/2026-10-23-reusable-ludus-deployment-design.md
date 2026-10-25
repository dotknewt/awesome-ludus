# Reusable Ludus deployment utility

Date: 2026-10-23  
Status: design approved by user; implementation pending. Implementation planning authorized; live activity remains separately gated.

## Intent and authority

Replace the one-off `/tmp/opencode/dev1-live-cycle-20261023/run_cycle.py` with a repository-owned Python utility that reliably deploys the selected range using roles from the active checkout. Avoid unnecessary uploads without mistaking a local ledger for proof of remote content, and separate launching a deployment from watching it.

This document authorizes no live activity, including read-only remote discovery. Only local files were consulted. The parent owns validation and dispatches the fresh builder check. Writing this design does not authorize implementation, deployment, monitoring, guest probes, cleanup, or retries.

Normative repository references:

- [Ludus authoring policy](../../instructions/ludus-authoring.md), especially role identity and static/live verification.
- [Live debugging policy](../../instructions/live-debugging.md), especially scope, force-upload, server verification, and one-request boundaries.

CLI examples below describe the proposed utility, not verified Ludus interfaces. The underlying CLI forms in the live-debugging policy are policy guidance; their version-specific behavior must be verified before implementation. No official-documentation or server compatibility verification was performed for this design.

## User decisions

- Repository-owned reusable Python utility; `ansible/roles` in the active checkout/worktree is the sole role source. An explicit checkout override is useful.
- Resolve every role referenced by the selected range's active configuration locally before any mutation. Missing or ambiguous roles block, even when installed remotely. Never guess identities by stripping namespaces or matching suffixes.
- Compare content, including uncommitted files, against a last-successful-upload ledger shared across worktrees and keyed by Ludus server and role. Unknown means changed.
- Default deploy lists changed/unknown roles, force-uploads only those, verifies installed identities, launches exactly one deployment, and exits without monitoring. No changed roles still means one deployment after successful preflight.
- Default scope is `roles`; `--scope full` is explicit. `DESTROYED` with roles scope blocks **before any upload**, explaining that full scope is required. Never silently widen scope.
- A separate monitor-only command cannot upload or deploy; it may observe until a terminal result. Observation timeout is unknown. No automatic deployment retries.
- Provide an explicit force override for stale ledger entries caused by out-of-tool uploads.

“Exactly one” applies to a successful deploy path, not failed preflight or uploads. Across failures, the enforceable local guarantee is at most one launch invocation per run; a lost response cannot prove whether the server accepted it.

## Goals, non-goals, and scope impact

Goals: deterministic role resolution and staging, conservative upload reuse, understandable failure evidence, worktree-safe shared state, and explicit launch/result distinction.

Non-goals: role installation from Galaxy or another checkout, automatic dependency repair, editing active range configuration, creating ranges, fixing failed roles, retry orchestration, guest diagnostics, or attesting remote role bytes without an authoritative facility. Do not turn the utility into a deployment service or scheduler.

Roles scope means the supported role deployment phase for the selected range, not an assertion that only changed roles or selected VMs execute. Full scope may run all configured deployment phases and affect the complete range. Both scopes use the same local-resolution, changed-upload, and identity-verification gates. Neither scope grants destructive cleanup, broader flags, or testing-mode overrides.

## Recommended shape (assistant recommendations, not user decisions)

Use one small CLI under `scripts/`, for example `scripts/ludus_deploy.py`, with standard-library subprocess, hashing, filesystem, locking, and JSON support. Reuse PyYAML if dependency review confirms it is suitable; the ad-hoc script already imports it, but no project-wide Python dependency contract has been established. Use safe YAML loading and reject malformed/ambiguous structures rather than permissive guessing.

Keep modules/functions focused on config discovery, resolution/staging, ledger/evidence, CLI adaptation, launch, and observation. Avoid a framework, daemon, or database unless concrete concurrency requirements demand one.

Proposed CLI:

```text
python scripts/ludus_deploy.py deploy --range RANGE
python scripts/ludus_deploy.py deploy --range RANGE --scope full
python scripts/ludus_deploy.py deploy --range RANGE --checkout /absolute/checkout
python scripts/ludus_deploy.py deploy --range RANGE --force-upload
python scripts/ludus_deploy.py monitor --run RUN_ID
python scripts/ludus_deploy.py monitor --run RUN_ID --wait --timeout SECONDS
```

Recommendation: `--force-upload` invalidates reuse for all configured roles in this invocation; it does not bypass resolution, scope, locks, presence checks, or authorization. Monitor defaults to a single observation; `--wait` polls with bounded intervals until correlated terminal evidence or timeout. No monitor flag changes deployment scope or enables mutation. A run ID binds monitoring to the recorded server, range, and launch context; do not default silently to whichever deployment is newest.

## Checkout and role resolution

1. Discover the active Git checkout from the invocation directory, including linked worktrees. Resolve `--checkout` explicitly when supplied. Fail outside a valid checkout without that override. Never infer the source from the script's own location, an old worktree path, the ledger, or temporary files.
2. Record canonical checkout/root and Git revision as provenance only. Git revision is not the content identity: tracked edits, deletions, and untracked uploadable content matter.
3. Fetch the selected range's **active** configuration through a version-verified adapter during an authorized invocation. Do not substitute a local blueprint. Record its digest and extract all configured role identities from supported schema locations and role-entry forms, including dependency references where applicable. Unsupported/dynamic identity forms block rather than silently disappear.
4. Index only directories contained in `<checkout>/ansible/roles`. Inspect metadata and exact names; require repository-mandated nonempty `galaxy_info.author` and `galaxy_info.role_name`. Resolve each configured identity uniquely, with an explanation of the evidence used.
5. Do not assume metadata `author` is necessarily a namespace or that a folder basename is the installed identity. For example, the current `linux_splunk_server` folder declares `role_name: linux_splunk_enterprise`. This is a discrepancy to reconcile, not permission to rewrite names automatically.
6. Recommendation: support a narrowly scoped, checked-in explicit identity-to-relative-directory mapping only for discrepancies that cannot be resolved from version-verified naming rules. Its filename/schema is a builder choice. Mapping cannot escape `ansible/roles`, suppress conflicting candidates, or assert compatibility without evidence. Report configured identity, folder, metadata, and conflict together. Multiple candidates, duplicate identities, missing sources, or unresolved namespace semantics block before mutations.
7. Validate relevant internal `include_role`/`import_role`, metadata dependencies, and configured ordering references for identity consistency under repository policy. Do not silently fetch dependencies. If static resolution cannot establish required identities, report the gap and block rather than infer compatibility.

An installed remote role is never a substitute for a missing local configured role. The same checkout can upload to multiple servers; worktrees targeting the same server/role share upload history. Different content in a second worktree becomes changed regardless of branch names.

## Content and staging contract

Recommendation: use a versioned SHA-256 manifest over sorted relative paths, entry types, content bytes, and relevant executable permission bits. Exclude timestamps, ownership, absolute paths, and Git commit IDs from content identity. Specify a small explicit exclusion list for VCS/cache artifacts; include other role files, including untracked files, regardless of `.gitignore`. Excluded artifacts must also be absent from the uploaded staging tree. A changed hash-policy version makes previous entries unknown.

Reject symlinks and special files initially, with a clear diagnostic; do not follow external sources. Restrict role identities used as staging basenames to validated safe path components. These are assistant-recommended conservative defaults, subject to builder review of real role contents and the verified uploader's packaging behavior.

Create a private per-run staging snapshot with each role directory named by its resolved exact installed identity, following the local live-debugging policy. Hash the **staged bytes actually supplied to the uploader**. Compare complete source manifests before and after copying, and verify the staging manifest against them; source churn blocks before uploads. Check staging integrity before each upload. The staged snapshot is authoritative for this run; later source edits belong to a later invocation and must not be recorded as uploaded. Prevent another process from modifying staging through permissions and retain no mutable source references.

## Ledger, evidence, and concurrency

Recommendation: use `${XDG_STATE_HOME:-$HOME/.local/state}/awesome-ludus/` for shared state, outside all worktrees. Store versioned JSON ledger entries keyed by canonical server identity and exact installed role identity, with an access/installation scope discriminator if research shows roles are not server-global.

A successful-upload entry records role identity, manifest digest/policy, server/scope key, upload run ID/time, checkout provenance, client/server versions, and post-upload identity evidence. It means “this tool successfully uploaded this snapshot and then observed the intended installed identity,” not “remote content is currently equal.” Presence checks cannot establish content attestation. Out-of-tool overwrites remain undetectable without authoritative content support; `--force-upload` addresses that limitation explicitly.

Use a server-wide interprocess exclusive lock for mutating runs (conservative until actual installation scope is established). Acquire before reading the shared ledger/preflight snapshot and hold through launch outcome recording. Fail clearly on contention; do not steal locks from a live owner. Kernel-released locks avoid stale lock-file ownership assumptions. Separate per-run evidence locking permits monitoring without initiating mutations. These locks coordinate this local state directory only, not other machines or independent Ludus clients.

Before each upload, durably mark the affected role unknown/in-flight. Commit its new successful entry only after command success and post-upload exact identity verification. Failure, timeout, interruption, unexpected response, or verification ambiguity leaves that role unknown; never restore the prior hash as if the upload could not have occurred. Confirmed earlier uploads may retain their entries when a later role fails, but no deployment launches. Unattempted roles retain their prior entries. Crash recovery treats all in-flight entries as unknown and never resumes mutations automatically.

Use atomic same-directory replacement and durable writes for ledger/run state. Unreadable, corrupt, incompatible, or insecure state is not a cache hit: block mutations with recovery guidance, or explicitly classify entries unknown after safe recovery. A failed durable state write stops further mutations.

Security recommendations:

- State/staging directories mode `0700`, files `0600`; verify ownership and reject unsafe symlinked paths. Keep run identifiers/path components independent of untrusted names.
- Never persist tokens, credential-bearing URLs, environment dumps, or raw active config. Store config digest and minimal nonsecret provenance. Reuse existing Ludus credential mechanisms without placing secrets in command arguments.
- Redact output **before** writing or displaying it. Key-name and literal-value replacement from the ad-hoc script is insufficient as a general guarantee; bound output, suppress unsafe payloads, and record minimal structured diagnostics when safe redaction is uncertain. Exceptions and subprocess errors must use the same path.
- Logs and role staging can contain secrets despite redaction. Keep private permissions, avoid repository evidence copies, document retention, and delete staging after completion/failure when no longer needed. Cleanup deletes only this run's local staging, not remote resources.
- Retain a small sanitized run manifest and command outcome journal sufficient for recovery. Evidence retention must not become an unbounded log archive.

## Deploy state machine

Recommended phases: `preflight → staged → uploading → verified → launch-reserved → launched`; failures record `blocked`, `upload-failed`, `launch-failed`, or `launch-unknown` with the last completed phase.

Preflight, under the lock, establishes server/access identity, versions/capabilities, active config and digest, local resolution, range status, installed-role presence, and ledger trust. All configured roles must resolve before any upload. `DESTROYED` plus roles scope blocks here and prints “Full scope required; explicitly request --scope full.” Unknown status, conflicting active deployment, unsupported state, or inability to establish safe targeting also blocks.

After staging, print the complete changed/unknown list and reasons: hash differs, no ledger, missing remotely, invalidated, policy changed, or explicit force. Unchanged requires both a matching trustworthy ledger entry and present exact remote identity. Zero changed roles is valid.

Force-upload changed/unknown roles only. Verify each successful upload's installed identity before ledger commitment; then verify all configured installed identities before launch. Recheck active config digest and range status before launch. If either invalidates preflight, stop, preserve confirmed upload evidence, and do not widen scope or rerun automatically. A range that becomes destroyed after uploads still blocks roles deployment; only the initially destroyed case can guarantee zero uploads.

Persist `launch-reserved` with invocation count one and the pre-launch correlation baseline **before** the single launch call. On confirmed acceptance, record `launched`, return the run ID/evidence path and optional monitor command, and exit. On definitive rejection, record launch failure. On timeout, disconnect, crash, or ambiguous acceptance, record unknown and never retry. Recovery of a reserved run observes only; it must not call deploy. If the server has no idempotency facility, do not imply exactly-once remote execution or race-free coordination with external clients.

## Monitor and correlation

The monitor adapter exposes read-only status/log operations only. It never calls uploader or launch logic, edits upload ledger entries, fixes failures, or retries deployment. Observation polling is not a deployment retry.

Record a pre-launch baseline (status, deployment identifier/timestamp or log cursor if available), launch request/response times, and any server-provided operation ID. Prefer an authoritative operation ID. Otherwise use version-verified evidence of a new run: status transition plus fresh log segment/recap tied to the selected range and launch window. A status that was already terminal before launch or an old `PLAY RECAP` is not this run's result. The ad-hoc script's broad terminal-name list and recap-substring check must not be inherited as a correctness rule.

Research must establish terminal states and success/failure semantics for the supported version. If run correlation cannot be established, report unknown, even when current status says success. If another deployment supersedes the run, report attribution lost/unknown rather than attaching its result. Timestamp-only heuristics must not be presented as definitive correlation.

`--wait` stops at correlated success/failure or observation limit. Timeout, interrupted observation, lost access, or insufficient evidence leaves deployment outcome unknown. Report the last observation and a monitor command; no redeploy suggestion as an automatic recovery action. Confirmed failure reports redacted host/role/task evidence where available and stops.

## Exit and reporting contract (recommendation)

| Code | Meaning |
| --- | --- |
| 0 | Deploy accepted (completion unobserved), or monitor confirmed terminal success; command/output distinguishes them. |
| 2 | Usage, preflight, resolution, scope, state-security, or lock blocker; deployment not launched. |
| 3 | Confirmed upload/verification or launch failure; report any partial uploads. |
| 4 | Outcome unknown, ambiguous launch, observation timeout, uncorrelated/nonterminal observation. |
| 5 | Monitor confirmed terminal deployment failure. |

Every summary includes command kind, run ID, server/range/scope, phase, mutation counts, outcome, and evidence location without credentials. Never print “deployment succeeded” on launch acceptance. State the error's uncertainty rather than turning nonzero CLI exit into an unverified claim about remote state.

## Documentation integration (future implementation work)

Add concise usage documentation and a repository entry-point link. Update `docs/instructions/live-debugging.md` and any `/live` integration to describe changed/unknown detection, force override, the new utility, and split observation. Its current mandatory upload→deploy→monitor cycle conflicts with the requested default launch-only behavior and must be reconciled explicitly: a launch-only request ends after acceptance; an explicitly requested observed cycle runs deploy once, then the monitor command. Preserve stop-on-failure, scope, separate diagnostic authorization, and unknown-on-timeout rules. Do not describe successful launch as completed verification.

## Builder research gates and verification

Before implementation, consult current official [CLI](https://docs.ludus.cloud/docs/cli), [roles](https://docs.ludus.cloud/docs/using-ludus/roles), [role development](https://docs.ludus.cloud/docs/developers/ansible-roles), and [configuration/schema](https://docs.ludus.cloud/schemas/range-config.json) references matched to the supported Ludus version. Record citations/version and remaining gaps. Obtain separate authorization before read-only remote discovery. Resolve:

1. Stable server identity across URL aliases, proxies, replacement instances, and ports; installation/access scope across users and ranges; safe cache partitioning when scope cannot be proven. Never merge uncertain identities into a trusted ledger key. Role overwrites may affect other ranges using the same identity: establish that sharing boundary and communicate it.
2. Actual upload naming/packaging/force semantics, identity collisions, metadata versus directory precedence, installed-list visibility, and whether response/presence evidence can identify the upload. Explicit mappings require these facts, not suffix heuristics.
3. Active-config retrieval/schema, all role-reference forms, version-specific deploy scope/acceptance behavior, busy/testing states, status terminal semantics, operation IDs/log cursors, and how reliably a launch can be correlated. Unsupported versions or missing essential evidence must block, not invent guarantees.
4. Dependency/runtime packaging for the local Python utility and whether conservative symlink/hash exclusions suit current roles. These are builder decisions unless they change user-visible source or scope guarantees.

Static verification can cover CLI/parser structure, mutation-free monitor call paths, config/resolver validation, manifest determinism, safe filesystem handling, and reviewed state-machine/error paths. Check changed artifacts with suitable file-scoped tools and retain exact commands/results. Do not add or rely on simulations, stateful fakes, or mocked server behavior as runtime evidence; static checks cannot prove upload, concurrency, or deployment behavior.

With **separate explicit live authorization**, exercise the actual utility/role entrypoints against an identified server/range: first upload, unchanged launch, uncommitted change, cross-worktree change, missing/ambiguous local resolution, destroyed+roles before uploads, explicit full, failed/ambiguous uploads, partial progress, launch ambiguity, and stale terminal/timeout monitoring. Exercise relevant concurrency and recovery paths without assuming permission to interrupt deployments or perform destructive setup. Use representative canary-bearing output through production sanitization before claiming sanitized evidence. No automatic retries; each additional mutating cycle requires authorization.

Report static checks, live checks, reused evidence with unchanged-artifact provenance, and unverified targets separately. This design has no live evidence and establishes neither selected-version compatibility nor deployment readiness. Unresolved material questions are the server/access sharing boundary, authoritative role identity rules, and available launch-correlation evidence; they are research gates rather than permission to relax the agreed behavior.
