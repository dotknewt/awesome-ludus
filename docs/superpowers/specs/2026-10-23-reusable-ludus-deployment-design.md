# Reusable Ludus deployment utility

Date: 2026-10-23  
Status: local implementation and whole-wave review complete; live verification pending and separately gated.

## Intent and authority

Replace the one-off `/tmp/opencode/dev1-live-cycle-20261023/run_cycle.py` with a repository-owned Python utility that reliably deploys the selected range using roles from the active checkout. Avoid unnecessary uploads without mistaking a local ledger for proof of remote content, and separate launching a deployment from watching it.

This document authorizes no live activity, including read-only remote discovery. The practical endpoint/user, explicit-reset, and selected-history adjustment is user-approved. Existing authorized research is recorded in the compatibility document; this revision performs no server calls. Parent owns validation. Writing this revision does not authorize implementation, deployment, monitoring, guest probes, cleanup, or retries.

Normative repository references:

- [Ludus authoring policy](../../instructions/ludus-authoring.md), especially role identity and static/live verification.
- [Live debugging policy](../../instructions/live-debugging.md), especially scope, force-upload, server verification, and one-request boundaries.

CLI examples below describe the proposed utility. Version-specific underlying Ludus arrays, source findings, authorized read-only evidence, and remaining verification limits are recorded in [compatibility research](../../research/reusable-ludus-deployment-compatibility.md).

## User decisions

- Repository-owned reusable Python utility; `ansible/roles` in the active checkout/worktree is the sole role source. An explicit checkout override is useful.
- Resolve every role referenced by the selected range's active configuration locally before any mutation. Missing or ambiguous roles block, even when installed remotely. Never guess identities by stripping namespaces or matching suffixes.
- Compare content, including uncommitted files, against a last-successful-upload ledger shared across worktrees and keyed by exact effective endpoint, authenticated user installation scope, and role. Unknown means changed. Default deploy resolves ambient CLI settings with no registration workflow.
- Default deploy lists changed/unknown roles, force-uploads only those, verifies installed identities, launches exactly one deployment, and exits without monitoring. No changed roles still means one deployment after successful preflight.
- Default scope is `roles`; `--scope full` is explicit. `DESTROYED` with roles scope blocks **before any upload**, explaining that full scope is required. Never silently widen scope.
- A separate monitor-only command cannot upload or deploy; it may observe until a terminal result. Observation timeout is unknown. No automatic deployment retries.
- Provide an explicit force override for stale ledger entries caused by out-of-tool uploads.
- Use one global local mutation lock and invalidate other endpoint/user entries for the same role before tool upload. After server replacement/restore, explicitly reset upload history; automatic replacement detection is not promised.
- Support reliable completion reporting for an explicitly selected history ID. Selection identifies the observed execution, not proof that a recorded launch created it; automatic `--run` attribution remains unknown when no authoritative binding exists.

“Exactly one” applies to a successful deploy path, not failed preflight or uploads. Across failures, the enforceable local guarantee is at most one launch invocation per run; a lost response cannot prove whether the server accepted it.

## Goals, non-goals, and scope impact

Goals: deterministic role resolution and staging, conservative upload reuse, understandable failure evidence, worktree-safe shared state, and explicit launch/result distinction.

Non-goals: role installation from Galaxy or another checkout, automatic dependency repair, editing active range configuration, creating ranges, fixing failed roles, retry orchestration, guest diagnostics, or attesting remote role bytes without an authoritative facility. Do not turn the utility into a deployment service or scheduler.

Roles scope means the supported role deployment phase for the selected range, not an assertion that only changed roles or selected VMs execute. Full scope may run all configured deployment phases and affect the complete range. Both scopes use the same local-resolution, changed-upload, and identity-verification gates. Neither scope grants destructive cleanup, broader flags, or testing-mode overrides.

## Recommended shape (assistant recommendations, not user decisions)

Use one small CLI under `scripts/`, for example `scripts/ludus_deploy.py`, with standard-library subprocess, hashing, filesystem, locking, and JSON support. Builder target is Python >=3.11 and PyYAML >=6.0,<7; observed Python 3.14.8/PyYAML 6.0.3 does not validate the older minimum. Initial credentials are LUDUS_API_KEY env-only; keyring-only users must securely set that environment variable. No keyring dependency or unverified backend is included. Use safe YAML loading and reject malformed/ambiguous structures.

Keep modules/functions focused on config discovery, resolution/staging, ledger/evidence, CLI adaptation, launch, and observation. Avoid a framework, daemon, or database unless concrete concurrency requirements demand one.

Proposed CLI:

```text
python scripts/ludus_deploy.py deploy --range RANGE
python scripts/ludus_deploy.py deploy --range RANGE --scope full
python scripts/ludus_deploy.py deploy --range RANGE --checkout /absolute/checkout
python scripts/ludus_deploy.py deploy --range RANGE --force-upload
python scripts/ludus_deploy.py monitor --run RUN_ID
python scripts/ludus_deploy.py monitor --run RUN_ID --wait --timeout SECONDS
python scripts/ludus_deploy.py monitor --range RANGE --history-id ID
python scripts/ludus_deploy.py monitor --range RANGE --history-id ID --wait --timeout SECONDS
python scripts/ludus_deploy.py reset-upload-history
```

`--force-upload` selects all configured roles without bypassing gates. `reset-upload-history` is an explicit local-only operation that invalidates all upload entries under the global lock, preserves run evidence, and reads no credentials or remote state. It never uploads or launches. Invoke it after server replacement/restore before relying on cached uploads. No registration or epoch workflow is required.

Monitor accepts mutually exclusive selectors: `--run RUN_ID`, or both `--range RANGE --history-id ID`. Both default to one observation; `--wait` polls with a bounded timeout. Explicit-ID mode resolves ambient endpoint/user once and pins them for the observation; run mode requires agreement with the recorded target. Neither follows the newest deployment or changes scope.

## Checkout and role resolution

1. Discover the active Git checkout from the invocation directory, including linked worktrees. Resolve `--checkout` explicitly when supplied. Fail outside a valid checkout without that override. Never infer the source from the script's own location, an old worktree path, the ledger, or temporary files.
2. Record canonical checkout/root and Git revision as provenance only. Git revision is not the content identity: tracked edits, deletions, and untracked uploadable content matter.
3. Fetch the selected range's **active** configuration through a version-verified adapter during an authorized invocation. Do not substitute a local blueprint. Record its digest and extract all configured role identities from supported schema locations and role-entry forms, including dependency references where applicable. Unsupported/dynamic identity forms block rather than silently disappear.
4. Index contained directories in `<checkout>/ansible/roles`; require nonempty `galaxy_info.author` and `galaxy_info.role_name`. Resolve exact folder `<roles>/<configured-identity>` first. Pinned api_ansible.go InstallRoleFromTar names from uploaded basename, with known archive suffixes stripped, not metadata. Reject unsafe components or names changed by that suffix stripping; stage with the configured exact identity.
5. `linux_splunk_server` therefore resolves to its exact folder despite metadata `linux_splunk_enterprise`; record disagreement but do not rename, block solely on it, or create a metadata-only competing candidate. Metadata author is not an inferred namespace. Internal/dependency references still require consistency checks.
6. Without an exact folder, require a checked-in explicit identity-to-contained-directory mapping (`ansible/role-identities.yml`, schema in plan). Namespaced identities without a full exact folder need such mapping; no suffix or metadata-only fallback. A mapping conflicting with an exact folder, duplicate identity, escape, or ambiguity blocks. Mapping cannot override an exact folder. Report configured identity, folder, metadata, and evidence together.
7. Validate relevant internal `include_role`/`import_role`, metadata dependencies, and configured ordering references for identity consistency under repository policy. Do not silently fetch dependencies. If static resolution cannot establish required identities, report the gap and block rather than infer compatibility.

An installed remote role is never a substitute for a missing local configured role. The same checkout can upload to multiple servers; worktrees targeting the same server/role share upload history. Different content in a second worktree becomes changed regardless of branch names.

## Content and staging contract

Recommendation: use a versioned SHA-256 manifest over sorted relative paths, entry types, content bytes, and relevant executable permission bits. Exclude timestamps, ownership, absolute paths, and Git commit IDs from content identity. Specify a small explicit exclusion list for VCS/cache artifacts; include other role files, including untracked files, regardless of `.gitignore`. Excluded artifacts must also be absent from the uploaded staging tree. A changed hash-policy version makes previous entries unknown.

Reject symlinks and special files initially, with a clear diagnostic; do not follow external sources. Restrict role identities used as staging basenames to validated safe path components. These are assistant-recommended conservative defaults, subject to builder review of real role contents and the verified uploader's packaging behavior.

Create a private per-run staging snapshot with each role directory named by its resolved exact installed identity, following the local live-debugging policy. Hash the **staged bytes actually supplied to the uploader**. Compare complete source manifests before and after copying, and verify the staging manifest against them; source churn blocks before uploads. Check staging integrity before each upload. The staged snapshot is authoritative for this run; later source edits belong to a later invocation and must not be recorded as uploaded. Prevent another process from modifying staging through permissions and retain no mutable source references.

## Ledger, evidence, and concurrency

Use `${XDG_STATE_HOME:-$HOME/.local/state}/awesome-ludus/` for shared state. `ServerKey.identity` is the exact credential-free effective endpoint; `access_scope` is `user:<authenticated-user-id>`, never range. Ledger key is `(ServerKey, exact_role_identity)`. Initial credentials require a nonempty LUDUS_API_KEY with exactly two nonempty dot-separated parts and a safe user prefix; ROOT/impersonation are unsupported. Pinned middleware verifies the full key against users.userID selected by prefix, then binds e.user from e.Auth; api_ansible.go installs under that user's ProxmoxUsername home. Successful authenticated config/role reads are required before discovery returns; prefix parsing alone is not authentication. Missing env key blocks with a secure set-env instruction, never silently falls back to keyring. Never persist keys/hashes. No registration is introduced.

### Private bound session and sanitized adapter boundary

`discover_target(range_id: str) -> BoundSession` resolves ambient settings once and returns a serializable `target: Target`, a read-only `read: ReadClient`, and an inaccessible-to-serialization private `ResolvedContext` binding the API key/proxy/verify/endpoint/executable and frozen child environment. No I/O constructor accepts Target alone. `enable_deploy(session: BoundSession) -> DeployClient` is explicit in deploy after preflight under the global lock; monitor only uses session.read. All clients share the frozen context; close the session on every exit. Neither context nor its repr, env, key, proxy secrets, or raw subprocess streams may enter records or exceptions.

Pinned child arguments append `--config /dev/null`, exact `--url`, explicit `--verify=true|false`, and `--user` with an empty argument. Remove inherited LUDUS_* and inject captured LUDUS_API_KEY/LUDUS_PROXY into a fixed allowlisted env snapshot; snapshot any supported standard proxy/certificate settings too. Resolve initial URL/proxy/verify from CLI-compatible env/config/default rules. Reject ambient impersonation; never re-read mutable config or credentials between discovery/upload/launch. Credential-bearing proxies stay env-only. See compatibility contract for exact arrays and failure semantics.

Only `UploadResult(disposition: confirmed|unknown|failure, message: sanitized string)` crosses the upload boundary. Private `_CommandResult` raw streams remain inside adapter. Exact successful source body is `{"result":"Successfully installed role"}` (HTTP 201); JSON-mode CLI can exit 0 on errors, so exit alone is insufficient. Confirmed wrapper still requires exact user-role presence before ledger commit. Source-traced pre-install denial/local pre-send failure may be failure; ambiguous transport/response or possible post-install error is unknown. No retry or restoration of invalidated upload history.

A successful-upload entry records role identity, manifest digest/policy, server/scope key, upload run ID/time, checkout provenance, client/server versions, and post-upload identity evidence. It means “this tool successfully uploaded this snapshot and then observed the intended installed identity,” not “remote content is currently equal.” Presence checks cannot establish content attestation. Out-of-tool overwrites remain undetectable without authoritative content support; `--force-upload` addresses that limitation explicitly.

Use one global interprocess exclusive mutation lock across all endpoint/user keys in the shared state root. Acquire before reading the shared ledger/preflight snapshot and hold through launch outcome recording; reset uses the same lock. Fail on contention; do not steal live locks. Separate evidence locks permit monitoring. This coordinates only the shared local state root, not other machines or independent clients. Exact endpoint keys do not detect aliases or replacement; undisclosed replacement at the same endpoint may evade presence checks. Explicit reset is the accepted recovery boundary.

Before each upload, durably mark the target role in-flight and invalidate every other endpoint/user entry for the same exact role name, conservatively covering aliases. All invalidation must finish before the remote call; state-write failure blocks. Commit only the target entry after command success and exact user-scoped identity verification; other entries remain unknown. Failure/timeout/interruption never restores old hashes. Earlier confirmed distinct-role uploads may remain committed if a later role fails, but no deployment launches. Unattempted distinct roles retain entries. Crash recovery treats in-flight as unknown and never resumes mutations automatically.

Use atomic same-directory replacement and durable writes for ledger/run state. Unreadable, corrupt, incompatible, or insecure state is not a cache hit: block mutations with recovery guidance, or explicitly classify entries unknown after safe recovery. A failed durable state write stops further mutations.

Security recommendations:

- State/staging directories mode `0700`, files `0600`; verify ownership and reject unsafe symlinked paths. Keep run identifiers/path components independent of untrusted names.
- Never persist tokens, credential-bearing URLs, environment dumps, or raw active config. Store config digest and minimal nonsecret provenance. Reuse existing Ludus credential mechanisms without placing secrets in command arguments.
- Redact output **before** writing or displaying it. Key-name and literal-value replacement from the ad-hoc script is insufficient as a general guarantee; bound output, suppress unsafe payloads, and record minimal structured diagnostics when safe redaction is uncertain. Exceptions and subprocess errors must use the same path.
- Logs and role staging can contain secrets despite redaction. Keep private permissions, avoid repository evidence copies, document retention, and delete staging after completion/failure when no longer needed. Cleanup deletes only this run's local staging, not remote resources.
- Retain a small sanitized run manifest and command outcome journal sufficient for recovery. Evidence retention must not become an unbounded log archive.

## Deploy state machine

Recommended phases: `preflight → staged → uploading → verified → launch-reserved → launched`; failures record `blocked`, `upload-failed`, `launch-failed`, or `launch-unknown` with the last completed phase.

Preflight, under the lock, establishes endpoint/user identity, versions/capabilities, active config and digest, local resolution, range status, installed-role presence, and ledger trust. All configured roles must resolve before any upload. `DESTROYED` plus roles scope blocks here and prints “Full scope required; explicitly request --scope full.” DEPLOYING/DESTROYING, testing enabled, malformed/unknown status, or unsafe targeting blocks. ERROR alone does not block under the researched source contract; other preflight checks still apply.

After staging, print the complete changed/unknown list and reasons: hash differs, no ledger, missing remotely, invalidated, policy changed, or explicit force. Unchanged requires both a matching trustworthy ledger entry and present exact remote identity. Zero changed roles is valid.

Force-upload changed/unknown roles only. Verify each successful upload's installed identity before ledger commitment; then verify all configured installed identities before launch. Recheck active config digest and range status before launch. If either invalidates preflight, stop, preserve confirmed upload evidence, and do not widen scope or rerun automatically. A range that becomes destroyed after uploads still blocks roles deployment; only the initially destroyed case can guarantee zero uploads.

Persist `launch-reserved` with invocation count one and the pre-launch correlation baseline **before** the single launch call. On confirmed acceptance, record `launched`, return the run ID/evidence path and optional monitor command, and exit. On definitive rejection, record launch failure. On timeout, disconnect, crash, or ambiguous acceptance, record unknown and never retry. Recovery of a reserved run observes only; it must not call deploy. If the server has no idempotency facility, do not imply exactly-once remote execution or race-free coordination with external clients.

## Monitor and correlation

The monitor adapter exposes read-only status/log operations only. It never calls uploader or launch logic, edits upload ledger entries, fixes failures, or retries deployment. Observation polling is not a deployment retry.

Record pre-launch status/history metadata and launch times. The researched acceptance response contains no history ID; history is created asynchronously. `monitor --run RUN_ID` therefore reports unknown and may list bounded safe candidate metadata (`id`, `status`, `start`, `end`, `created`) for that range. Never attach a candidate automatically, persist it as the run's operation ID, or infer attribution from timestamp, transition, newest entry, or recap.

`monitor --range RANGE --history-id ID` observes exactly the selected record through session.read.history_list metadata; initially no raw-log/detail lookup is exposed. Pinned range history lists all retained records without pagination; retention defaults to 10 and may prune an ID. Missing/duplicate/pruned ID, truncated capture, unknown status, or unsupported pagination wrapper yields unknown, never latest fallback. `success` is selected-history success; `failure`/`aborted` selected failure; `running` nonterminal. The separately researched detail DTO does contain status and result, but is unnecessary here. These results identify the selected execution, not a utility launch.

`--wait` stops at selected-history terminal success/failure or observation limit. Run-based attribution remains unknown on the researched pair. Timeout, interruption, lost access, or insufficient evidence leaves outcome unknown. Report last observation and a monitor command, not an automatic redeploy action. Selected failure reports redacted host/role/task evidence where available and stops.

## Exit and reporting contract (recommendation)

| Code | Meaning |
| --- | --- |
| 0 | Deploy accepted (completion unobserved), selected-history terminal success, or local reset success; output distinguishes them. |
| 2 | Usage, preflight, resolution, scope, state-security, or lock blocker; deployment not launched. |
| 3 | Confirmed upload/verification or launch failure; report any partial uploads. |
| 4 | Outcome unknown, ambiguous launch, observation timeout, uncorrelated/nonterminal observation. |
| 5 | Selected-history terminal failure or aborted execution. |

Summaries identify command kind, observation/run ID, endpoint/user/range where applicable, scope when known, phase, mutation counts, outcome, and evidence location. Selected-history summaries include history ID and `user-selected` attribution; no invented launch run/scope. Reset reports invalidated-entry count and no remote actions. Reset success uses exit 0; invalid local state/lock uses exit 2. Never print “deployment succeeded” on launch acceptance.

Accepted launch output includes `Accepted; completion unobserved`, run ID, and `python scripts/ludus_deploy.py monitor --run RUN_ID`. Explain that this can show candidate metadata but cannot automatically bind a history ID. After selecting an execution, the user runs `python scripts/ludus_deploy.py monitor --range RANGE --history-id ID [--wait --timeout SECONDS]`; this reports only the selected execution's completion.

## Documentation integration (future implementation work)

Add concise usage documentation and a repository entry-point link. Update `docs/instructions/live-debugging.md` and any `/live` integration for changed/unknown detection, force/reset, and split observation: launch-only ends after acceptance; an explicitly requested observed cycle deploys once then monitors. On this pair, --run cannot prove completion; explicit history selection is needed to report a selected execution's result, and the integration must not auto-pick an ID. Preserve stop-on-failure, scope, separate diagnostic authorization, and unknown-on-timeout. Never describe launch acceptance as completed verification.

## Builder research gates and verification

Before implementation, consult current official [CLI](https://docs.ludus.cloud/docs/cli), [roles](https://docs.ludus.cloud/docs/using-ludus/roles), [role development](https://docs.ludus.cloud/docs/developers/ansible-roles), and [configuration/schema](https://docs.ludus.cloud/schemas/range-config.json) references matched to the supported Ludus version. Record citations/version and remaining gaps. Obtain separate authorization before read-only remote discovery. Resolve:

1. Implement source-verified API-key prefix/authentication chain using env-only credentials and private bound session; unsupported keyring-only discovery blocks. Use global locking, cross-key invalidation, and explicit reset after replacement, not automatic generation detection. Communicate shared-role impact.
2. Actual upload naming/packaging/force semantics, identity collisions, metadata versus directory precedence, installed-list visibility, and whether response/presence evidence can identify the upload. Explicit mappings require these facts, not suffix heuristics.
3. Active-config/schema, role forms, deploy scope/acceptance, busy/testing, and history-list decoding. Selected-history status requires an exact range-scoped ID match; missing/pruned entries remain unknown. No raw detail lookup initially. Automatic launch attribution stays unknown-only. Validate exact upload success/error parsing despite JSON CLI exit 0; unsupported versions/shapes block.
4. Dependency/runtime packaging for the local Python utility and whether conservative symlink/hash exclusions suit current roles. These are builder decisions unless they change user-visible source or scope guarantees.

Static verification can cover CLI/parser structure, mutation-free monitor call paths, config/resolver validation, manifest determinism, safe filesystem handling, and reviewed state-machine/error paths. Check changed artifacts with suitable file-scoped tools and retain exact commands/results. Do not add or rely on simulations, stateful fakes, or mocked server behavior as runtime evidence; static checks cannot prove upload, concurrency, or deployment behavior.

With **separate explicit live authorization**, exercise the actual utility/role entrypoints against an identified server/range: first upload, unchanged launch, uncommitted change, cross-worktree change, missing/ambiguous local resolution, destroyed+roles before uploads, explicit full, failed/ambiguous uploads, partial progress, launch ambiguity, and stale terminal/timeout monitoring. Exercise relevant concurrency and recovery paths without assuming permission to interrupt deployments or perform destructive setup. Use representative canary-bearing output through production sanitization before claiming sanitized evidence. No automatic retries; each additional mutating cycle requires authorization.

Report static checks, live checks, reused evidence and unverified targets separately. Compatibility research includes authorized read-only evidence plus direct pinned-source auth/naming/upload/history contracts, not live deployment verification. Initial scope is env-only credentials and metadata-only observation; keyring interoperability is not claimed. Session isolation, result sanitization, runtime minima and actual-entrypoint behavior need implementation verification. Parent review remains required.
