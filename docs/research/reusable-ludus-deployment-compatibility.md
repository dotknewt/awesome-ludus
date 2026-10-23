# Reusable Ludus deployment compatibility gate

Date: 2026-10-23

**Task 1: DONE_WITH_CONCERNS — practical endpoint/user and explicit-history adjustment approved by user; revised documents await parent review before code.**

The selected client and server are both **`2.3.10+fccf931e`**. Authorized read-only checks establish selected-range config/status/history shapes and visible role identities. Upload and deployment behavior below is researched source behavior, not live mutation verification. The [approved design][design] and [plan][plan] are updated alongside this document for the user's practical endpoint/user, explicit-reset, and selected-history decision.

## Evidence provenance and bounds

| Label | Provenance |
| --- | --- |
| E | Writer read all 66 lines of `.superpowers/sdd/2026-10-23-reusable-ludus-deployment/read-only-evidence.txt`. These are parent-supplied, user-authorized read-only observations, not calls performed by this writer. Corrections at lines 55–66 supersede the initial empty version, empty role-reference extraction, and broad server-version match. |
| W | This writer fetched public pinned `ludus-client/cmd/range.go`, `ansible.go`, `root.go`, and `ludus-api/api_range_management.go` on 2026-10-23. URLs below pin commit `fccf931e94e76f4d174211a99d44daa3bc505ce9`; raw fetches used the equivalent `/-/raw/` URLs. |
| L | Librarian-reported findings supplied by parent: official tag **2.3.10** at that commit ([tags][tags]); packaging, API role installation/precedence, schema, and history creation/lookup. These remain attributed, not independently checked by this writer. |
| P | Parent independently fetched pinned `root.go` and `dto/responses.go`, reporting configuration/credential selection and `global,omitempty`. User approved exact endpoint/user records, explicit local reset after replacement, global locking, same-role cross-key invalidation, and explicit-history monitoring. These local policies are not official Ludus guarantees. |
| F | Supplied local binary SHA-256: `5bc6021744acd0753a520f2c98e593190d329bdc4ea43e6413aefcd926c1af79`. Not recomputed by this writer; not a server identity. |

**R1 correction/evidence:** this writer additionally fetched pinned `ludus-api/api_ansible.go`, `middleware.go`, `routers.go`, `utils.go`, `errors.go`, `dto/responses.go`, `api_log_history.go`, and `ludus-client/cmd/utils.go`. These direct reads supersede the librarian's incorrect installation-handler citation: **InstallRoleFromTar is in api_ansible.go, not ansible.go**. `ansible.go` is retained only as the separately attributed range-execution/history-creation reference. Source-contract verification below is not live verification.

E records client version via `ludus version` (semantic version on stderr) and corrected server-labeled version via `ludus version --verbose`. Both are `2.3.10+fccf931e`; the unrelated `1.26.3` match is superseded, not a second supported server. The earlier setup's unsupported version invocation is not verification evidence.

No additional server calls were made by this writer. Authorized read-only calls did occur in the parent evidence; no upload, deployment, guest probe, or other live mutation was exercised for this research. No credentials or raw active config are copied into this deliverable.

## Version-specific evidence and adapter rules

All source rows below apply to commit `fccf931e94e76f4d174211a99d44daa3bc505ce9`, matching the observed pair. Documentation/schema URLs are unversioned and retain that limitation.

| Operation/field | Evidence and reference | Implementable rule | Remaining limitation |
| --- | --- | --- | --- |
| Client/server version | E lines 55, 59–61, 66: both `2.3.10+fccf931e` | Initially support only this researched pair; unexpected/missing versions block rather than selecting a nearest version. Parse the server-labeled version only. | No other pair tested or researched here. |
| Role upload arguments | W: setupRoleCmd binds --directory/-d, --force/-f, --global/-g; genericRoleCmd sends basename and force/global to /ansible/role/fromtar ([client ansible.go][client-ansible]); R1 router registers PUT. | Use exact upload array below; no positional Galaxy role, global flag, or impersonation. Force only changed/unknown roles. | No live upload or partial-failure test. |
| Installation identity and scope | R1: `InstallRoleFromTar`, `roleNameFromUploadedArchiveBasename`, `parseRoleVersion`, `GetRolesAndCollections`, `GetRoleVars` in [api_ansible.go][api-ansible-handler]; client basename and tar helper in [client ansible.go][client-ansible]/[utils.go][utils]. | Exact-folder-first resolution, stage basename equals configured identity; reject identities changed by archive-suffix stripping. Metadata author/role_name do not override the filename identity. Default installation uses authenticated user's ProxmoxUsername-backed Ansible home; explicit global only. | Source-researched, not live mutation verification. Presence cannot attest content. |
| Role list | E: JSON array of 25 entries, including roles and collections; string `name`, `type`, `version`; `global` omitted. P: DTO declares boolean `json:"global,omitempty"` ([responses.go][responses]). | Filter `type == "role"`; missing `global` means false for this pinned DTO, not unknown. If present require boolean; explicit null/wrong type blocks. Treat version string `"null"` as a string, not a digest. | E's displayed `global: None` came from absent-field extraction; it does not establish JSON null. No global=true entry was observed. |
| Packaging | R1: `tarDirectoryInMemory` walks entries without VCS exclusions and preserves basename root ([utils.go][utils]); client sends basename. | Apply local exclusions to stage and manifest consistently. Hash staged bytes, include other untracked files, reject symlinks/special files. | Helper does not propagate the Walk return error; a normal process exit alone cannot attest archive integrity. Local staging checks and later actual-entrypoint validation remain required. |
| Active config | E: `{ "result": <YAML string> }`; top-level defaults/global_role_vars/ludus/router; corrected extraction finds eight role identities. W: `rangeConfigGet`, `GetConfig` ([range.go][range], [range management][management]). | Strictly decode result string and YAML; require supported shapes and exact role/dependency resolution. Do not substitute a blueprint. | Read-only evidence is one active config, not exhaustive parser coverage. |
| Config role forms | L: string entries or `name` plus `depends_on` entries using `vm_name` and `role` ([schema][schema]) | Extract configured identities and dependencies; malformed/dynamic/ambiguous forms block. | Unversioned schema guidance; unsupported forms must not silently disappear. |
| Status | E: object with `rangeID` string, `rangeState` string, `lastDeployment` string, `testingEnabled` boolean; selected `dev1` was `ERROR`, testing false. W: state constants and `DeployRange` ([management][management]). | Match requested range; block DEPLOYING/DESTROYING, testing true, unknown states or malformed fields. Do not block solely because state is ERROR. | Observation is not a new deployment result or a promise that deploy will succeed. |
| Deploy scope/acceptance | W: `user-defined-roles` accepted tag; omitted tags become `all`; `DeployRange` returns HTTP 200 `JSONResult(..., "Range deploy started")` after scheduling goroutine ([range][range], [management][management]). P/L: JSON result wrapper, no history ID. | Use exact roles/full arrays below; acceptance is `{ "result": "Range deploy started" }`, not completion. At most one launch invocation; ambiguous result means unknown, no retry. | No live launch acceptance/failure-path verification. No verified idempotency mechanism. |
| History/correlation | E array; R1 `GetRangeLogHistory` returns all retained entries filtered by selected range record, without pagination; `maxLogHistoryEntries` defaults retention to 10. R1 DTO/detail handler confirms id/status/start/end/created/result ([history][history], [responses][responses], [utils][utils]). | Initial observer uses exact-ID metadata only; no raw-log/detail method. Missing/pruned/duplicate ID, truncated output, or unsupported pagination wrapper yields unknown. Automatic launch attribution remains unknown-only. | Detail API exists but is intentionally outside initial adapter; no detail-decoding blocker. No launch-to-history binding. |
| Endpoint/authentication | R1 [middleware.go][middleware]: split key into exactly two parts, lookup users.userID by prefix, verify full key hash, set e.Auth; userAndRangesLookupMiddleware sets e.user from e.Auth unless impersonating. [routers.go][routers] binds middleware before handler; [api_ansible.go][api-ansible-handler] uses e.user.ProxmoxUsername. | Initial utility supports nonempty LUDUS_API_KEY only, with exact-two-part safe prefix; no impersonation, no keyring fallback. Successful authenticated range/role reads validate this binding before cache reuse/mutation. | Keyring-only users receive an explicit set-env instruction. No new dependency or assumed interoperability. Prefix alone is not successful authentication. Replacement still requires explicit reset. |

The active-config SHA-256 in E is `f8b73849c0cbfd9dd8aabcc11766fab17058c1b291134a118b5dc487c6b510da`. Corrected role identities are `linux_gitlab_ce`, `linux_logging`, `linux_splunk_server`, `ludus_gitlab_runner`, `ludus_k3s_bootstrap`, `splunk_container_logs`, `splunk_forwarder`, and `windows_logging_policy`. All appear in the observed role list. That establishes visible installed names, not local source resolution or byte equality. The empty initial `role_reference_fields` result is superseded by E line 64.

## Deterministic local naming contract

The verified chain is client `genericRoleCmd` → `tarDirectoryInMemory(stage)` (basename-root tar) and filename `filepath.Base(stage)` → router **PUT /api/v2/ansible/role/fromtar** → `api_ansible.go::InstallRoleFromTar` → repeated known-archive-suffix stripping → galaxy role install with that name in the authenticated user's Ansible home → parseRoleVersion at the directory with that name. Handler naming does not read galaxy_info.author/role_name. Restrict role identities to safe path components and reject any identity changed by case-insensitive stripping of `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.tgz`, `.tbz2`, `.txz`, `.tar`, `.zip`, `.gz`, `.bz2`, `.xz`, `.zst`; dots in ordinary namespaces remain intact.

Resolution order for configured identity R:

1. Prefer the contained exact directory `<checkout>/ansible/roles/R`, with mandatory metadata fields still validated. Metadata name disagreement is recorded but does not create a competing installed identity under this pinned upload contract.
2. If no exact directory exists, require a checked-in explicit mapping from R to a contained relative role directory. Never derive `author.role_name`, strip a namespace, suffix-match, or select solely by metadata.
3. If an explicit mapping conflicts with an existing exact directory, duplicates an identity, escapes the role root, or is ambiguous, block rather than let it override. Metadata-only coincidences do not defeat a valid exact-folder match. Validate internal/dependency references independently.

Thus configured `linux_splunk_server` resolves to folder `linux_splunk_server` despite metadata `linux_splunk_enterprise`, then stages/uploads as `linux_splunk_server`. A namespaced identity resolves automatically only when its full exact folder exists; otherwise it requires an explicit mapping. This closes the prior metadata mismatch gate using source evidence, not name guessing or metadata edits.

## Exact command arrays

These are argv arrays, not shell strings. `range`, `stage`, and `history_id` below are single validated string arguments. E arrays used range `dev1`. Mutation arrays are source-verified contracts only and were not executed.

| Purpose | Exact argv | Evidence |
| --- | --- | --- |
| Client version | `["ludus", "version"]` | E 1, 55 |
| Version help | `["ludus", "version", "--help"]` | E 59 |
| Server version | `["ludus", "version", "--verbose"]` | E 60, 66; parse server-labeled semantic version, suppress raw verbose output |
| Active config | `["ludus", "range", "config", "get", "--range", range, "--json"]` | E 3, 62; W `rangeConfigGet` |
| Status | `["ludus", "range", "status", "--range", range, "--json"]` | E 8; W alias for `range list` |
| Installed roles | `["ludus", "ansible", "role", "list", "--range", range, "--json"]` | E 16; W `rolesListCmd` |
| History baseline | `["ludus", "range", "logs", "--history", "--range", range, "--json"]` | E 43; W `setupRangeLogsCmd`; L history handler |
| Historical log lookup (researched, excluded from initial adapter) | `["ludus", "range", "logs", "--id", history_id, "--range", range, "--json"]` | R1 displayLogHistory and GetRangeLogHistoryByID; DTO id/status/start/end/created/result; no live execution |
| Upload changed/unknown role | `["ludus", "ansible", "role", "add", "--directory", stage, "--force", "--json"]` | W `genericRoleCmd`, `setupRoleCmd`; L default authenticated-user install |
| Launch roles scope | `["ludus", "range", "deploy", "--range", range, "--tags", "user-defined-roles", "--json"]` | W `setupRangeDeployCmd`, `rangeDeployCmd`, `DeployRange` |
| Launch full scope | `["ludus", "range", "deploy", "--range", range, "--json"]` | W omitted tags default to `all` |

Root persistent `--range` and `--json` are confirmed in W `root.go`. Upload deliberately has no range selector: installation is authenticated-user scoped. It must run under the same bound endpoint/authentication context as the range reads. `--force` here applies to role replacement only; never add it to deploy. Do not add `--global`, a nonempty `--user` impersonation value, `--only-roles`, `--limit`, abort, or testing overrides. The bound transport explicitly supplies `--user ''` (an empty argv value) to pin no impersonation.

Default `deploy --range RANGE` resolves ambient endpoint/proxy/verify once without registration. **Initial credential support is env-only:** require nonempty `LUDUS_API_KEY`; if absent stop before remote calls with “Set LUDUS_API_KEY securely in this process environment; keyring-only credentials are not supported by this utility yet.” Do not fetch/print a key or suggest embedding one in shell history. Require exactly one dot with nonempty parts and a control-free safe user-ID prefix; reject ROOT and impersonation as unsupported local policy. The middleware source proves prefix-to-user binding only after full-key authentication succeeds. Authorized discovery must successfully read selected config and installed roles through this same credential before returning a bound target; merely parsing the prefix or reading a version is insufficient.

### Bound transport contract

- Private `ResolvedContext` holds immutable endpoint, effective_user, API key, proxy, verify, resolved executable path, and a copied child environment. No repr/serialization/persistence; never place the key or credential-bearing proxy in argv. Public `Target` holds only ServerKey/range/capabilities. Reset/help construct neither.
- `discover_target(range_id: str) -> BoundSession` resolves settings/credentials once, verifies supported versions and authenticated read shapes, and returns `BoundSession.target` plus `BoundSession.read: ReadClient`. It retains the private ResolvedContext. No public constructor accepting only Target can perform I/O.
- `enable_deploy(session: BoundSession) -> DeployClient` is called explicitly by the deploy workflow after preflight under the global lock; monitor receives only `session.read` and never this mutating capability. DeployClient and ReadClient share the same frozen context, never re-resolve environment/config/keyring. `BoundSession.close()` releases transient references on all exit paths; no claim of guaranteed Python memory zeroization.
- Child argv is each base array above plus `["--config", "/dev/null", "--url", context.endpoint, "--verify=" + ("true" if context.verify else "false"), "--user", ""]`. `/dev/null` prevents mutable ambient config from re-entering resolution. Initial resolution mirrors root defaults/env/config for URL/proxy/verify; unsupported/malformed config blocks rather than guesses. Reject nonempty ambient LUDUS_USER or config user; there is no utility impersonation option. Explicit empty --user also prevents a query userID.
- Child env is a frozen allowlisted snapshot, not os.environ at call time: retain required process basics (PATH/HOME/locale/temp and approved certificate settings) and captured standard proxy variables if used; remove all ambient LUDUS_* then inject only captured LUDUS_API_KEY and LUDUS_PROXY. URL/verify/user are fixed by argv; empty proxy falls back only to the already snapshotted standard proxy settings. Suppress raw verbose output. Never dump env/config/context in errors. All calls, including version discovery, use this transport; no keyring fallback can occur with the required nonempty env key.

### Upload response boundary

R1 `InstallRoleFromTar` returns HTTP **201** via `JSONResult` with exact body **`{"result":"Successfully installed role"}`** after install and parseRoleVersion. `JSONError` produces `{"error": message}` ([errors.go][errors]). Critically, client `checkSuccessAndProvideJSON` prints JSON and exits **0 before checking success** ([utils.go][utils]); process exit 0 is not an upload success signal.

`DeployClient.upload(role: StagedRole) -> UploadResult(disposition: Literal['confirmed','unknown','failure'], message: str)` exposes only a bounded sanitized message, no stdout/stderr/body. Raw `_CommandResult` stays private inside the adapter. `confirmed` requires exit 0, complete valid exact success wrapper (no error), and no capture/timeout ambiguity; workflow still verifies exact user-role presence before committing ledger. `failure` is allowed for known local pre-send rejection or an exact source-traced pre-install denial (`You are not authorized to perform this ansible action`, `Only administrators can perform global ansible actions`). All transport/parse/capture failures, nonzero exits after possible invocation, unexpected wrappers, and other error responses are `unknown`, since error paths may occur after installation. Any attempted upload without confirmed result stops deployment and leaves ledger unknown; confirmed denial does not restore prior invalidated entries. Never relay server error text unless sanitized; generic fixed messages are sufficient. This source contract does not attest uploaded bytes.

For CLI results, require successful process completion and the expected structured response, not merely a substring or exit status. Unexpected output, malformed JSON, disconnect, or timeout after possible mutation leaves affected entries/run outcome unknown. The researched JSON acceptance shape is not an exactly-once guarantee.

## State eligibility and run attribution

Pinned constants: `DEPLOYING`, `DESTROYING`, `ERROR`, `ABORTED`, `DESTROYED`, `NEVER DEPLOYED`, `SUCCESS`. W `DeployRange` rejects DEPLOYING, DESTROYING, and testing enabled when force is false. It does **not** reject ERROR solely on state. ERROR, ABORTED, NEVER DEPLOYED, and SUCCESS may proceed through the utility's other preflight checks; this is not guaranteed server acceptance, since authorization, config, entitlement, quota, and other checks can still fail. Unknown states block.

The local approved design additionally blocks DESTROYED with roles scope **before uploads**, requiring explicit full scope. Full scope can pass this state gate, subject to all other checks. Recheck config digest/status before launch. No scope widening or automatic retry is permitted.

History is created asynchronously after launch scheduling; acceptance carries no history ID. Supported automatic correlation mode is **`unknown-only`**. The monitor can report current status/history as observations, but must not mark the accepted run successful/failed based on timestamp proximity, new history ID, state transition, newest entry, or recap text. No authoritative binding has been established. Timeout, supersession, ambiguous acceptance, interrupted observation, or lost access remain unknown. A historical failure in E does not belong to a new utility run.

Explicit selection is separately supported: `monitor --range RANGE --history-id ID [--wait --timeout SECONDS]` pins ambient endpoint/user/range and observes exactly ID. It may report `success` as success and `failure`/`aborted` as failure for **that selected execution**, never as proof of a tool launch. `running` is nonterminal; missing/ambiguous ID, unavailable metadata, unknown status, timeout, or lost access yields unknown. A newer range deployment does not change the selected ID. Default observation is one-shot; optional wait polls only reads.

`monitor --run RUN_ID` is mutually exclusive with explicit range/history selection. It may list bounded safe candidates (`id`, `status`, `start`, `end`, `created`) but never attaches one automatically or mutates the launch's operation ID. Acceptance output shows `Accepted; completion unobserved`, run ID, and `python scripts/ludus_deploy.py monitor --run RUN_ID`. Explain that the user may then choose `python scripts/ludus_deploy.py monitor --range RANGE --history-id ID`; the choice identifies the observation target, not launch provenance.

### Selected-history interfaces

- `ReadClient.history_list() -> tuple[HistoryEntry,...]` returns range-scoped validated ID/status/timestamp metadata from the researched history array.
- No history_detail/raw-log lookup is exposed initially. R1 confirms its DTO actually includes status as well as result, correcting prior uncertainty, but missing log files can make detail fail even when metadata exists; metadata-only is sufficient for this contract.
- `observe_history(history_id: str) -> Observation` selects exactly one ID from complete range-scoped metadata. GetRangeLogHistory has no pagination parameters (limit/offset 0,0); retention prunes old rows, default 10. Missing/pruned/duplicate IDs, capture truncation, unsupported wrappers, or malformed statuses yield unknown, never newest fallback. Preserve safe timestamps without treating them as attribution.
- `observe_run(run: RunRecord) -> Observation` emits unknown attribution and safe candidate metadata. `Observation` includes target, history_id, history_status, attribution (`unknown` or `user-selected`), optional snapshot, and candidates; no raw logs.
- `monitor(*, run_id: str | None, range_id: str | None, history_id: str | None, wait: bool, timeout: float, store: StateStore) -> Summary` validates selectors, calls discover_target(selected_range) once and uses only session.read, closing on exit. Run mode requires session.target agreement with recorded target. It records separate ObservationRecord evidence, never edits upload history or attaches IDs to a launch. Selected-history mode requires no prior RunRecord. Full interfaces are in the plan.

## Approved endpoint/user upload-history contract

No mandatory registration or epoch workflow. `ServerKey(identity, access_scope)` uses the exact credential-free effective endpoint (including port/path, no alias merging) and `user:<validated-effective-user-id>`. Never use range ID as installation scope. Upload key is `(ServerKey, exact_role_identity)`. Reject credential-bearing endpoints and unknown user identity. A run records this key and cannot silently retarget.

Automatic server replacement detection is not available from the researched interfaces. The user explicitly accepts **`reset-upload-history` after replacement/restore** before trusting prior upload records. Undisclosed replacement at an unchanged endpoint can evade presence checks. Reset is local-only, invalidates all upload entries, preserves run/observation evidence, and requires explicit invocation; it reads no credentials and makes no remote calls. It is not run automatically during deploy/monitor. `--force-upload` still uploads all configured roles without bypassing preflight.

### Global mutation lock and conservative invalidation

- `StateStore.mutation_lock()`: one kernel-backed exclusive lock across **all endpoint/user keys** in the shared state root. Acquire before ledger/preflight reads and hold through launch recording. Reset uses the same lock. Contention blocks; do not steal a live lock.
- `StateStore.begin_upload(entry: UploadEntry)`: under that lock, durably mark target in-flight and invalidate every other endpoint/user entry for the same exact role identity. Over-invalidation is intentional because alias equivalence is unknown. Complete all writes before remote upload; state-write failure blocks.
- `StateStore.save_entry(entry)`: commit only the target key after command success and exact user-role presence verification. Other entries remain unknown; ambiguous/failed uploads never restore old hashes. Crash recovery treats in-flight as unknown and never resumes mutation automatically.
- `StateStore.reset_upload_history() -> int`: under the global lock durably invalidate all upload entries and return their count; preserve run/observation records. Workflow `reset_upload_history(store) -> ResetSummary` acquires the lock and invokes only this local state operation. Lock/state failure blocks with safe diagnostics, not partial-success claims.
- Locks/invalidation cover only clients sharing this local state root. Other machines, other state roots, and out-of-tool mutations remain outside coordination. They cannot be advertised as race-free server locking or remote attestation.

User-role replacement can affect all ranges using that user's role identity; global roles can have broader impact and user roles shadow them. This utility installs only user roles. Presence of only a global role does not establish a matching prior user upload; require user-scoped evidence before ledger reuse. Unknown local resolution still blocks even when a remote role is visible.

## Local runtime and packaging target

E line 65 observes **Python 3.14.8**, **PyYAML 6.0.3**, and **zero symlinks under local `ansible/roles`**. Select **Python >=3.11** and **PyYAML >=6.0,<7** as the builder target, not an official Ludus dependency requirement. Python 3.11–3.13 and other allowed PyYAML versions are unverified; implementation must avoid newer-only APIs and validate the declared minimum before claiming that runtime tested.

Retain the proposed initial rejection of symlinks/special files; current local evidence shows no symlink requirement to accommodate. Exclude `.git`, `__pycache__`, and `*.pyc` consistently from staging/manifests. Include other uploadable untracked content regardless of `.gitignore`. The uploader itself does not provide these exclusions (L). Hash private staged bytes and verify source/stage consistency per design; implementation tests remain future work.

## Completion, concerns, and authorization

Closed for Task 1: selected version pair, read argv/observed shapes, visible configured-role identities, omitted-global decoding, per-user naming/scope source contract, exact upload/deploy argv and scope, ERROR eligibility, busy/testing checks, acceptance distinction, unknown-only automatic attribution with explicit-history selection, approved endpoint/user/global-lock/reset contract, runtime target, and current symlink observation.

Concerns carried to parent review:

1. **Parent review and declared limits:** prefix-to-authenticated-user chain is source-verified; initial credential support is env-only, keyring interoperability intentionally unsupported. Initial observer uses verified history metadata only. Missing identity/ID remains blocked/unknown. BoundSession and UploadResult contracts need implementation/static checks; code remains outside this documentation authorization.
2. **Runtime not demonstrated:** upload/replacement/failure paths, deploy acceptance, convergence, concurrency/recovery, sanitization, and monitoring behavior were not exercised. These are later separately authorized checks, not prerequisites for completing this research handoff.
3. **Version/documentation coverage:** R1 directly verifies packaging, authentication/install handlers, history list/detail DTO, and global omission, replacing those earlier attributed-only claims. Async creation inside range execution remains librarian-reported. [CLI][cli], [roles][roles], [schema][schema], and [role development](https://docs.ludus.cloud/docs/developers/ansible-roles) remain reference links, not fresh writer checks. Repository metadata requirements are policy; unsupported structures fail closed.
4. **Local minimum runtime:** the declared builder baseline has not been exercised on Python 3.11. No test result is claimed merely from version observation.

Static/public-source verification and reused authorized read-only server evidence are distinguished above. No deployment-readiness claim is made. Parent independent review follows. No more server checks are requested or authorized by this document; future calls retain their separate authorization boundary and must not use administrator impersonation or broader access.

[tags]: https://gitlab.com/badsectorlabs/ludus/-/tags
[client-ansible]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-client/cmd/ansible.go
[root]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-client/cmd/root.go
[utils]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-client/cmd/utils.go
[range]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-client/cmd/range.go
[api-ansible]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/ansible.go
[api-ansible-handler]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/api_ansible.go
[middleware]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/middleware.go
[routers]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/routers.go
[errors]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/errors.go
[responses]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/dto/responses.go
[management]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/api_range_management.go
[history]: https://gitlab.com/badsectorlabs/ludus/-/blob/fccf931e94e76f4d174211a99d44daa3bc505ce9/ludus-api/api_log_history.go
[roles]: https://docs.ludus.cloud/docs/using-ludus/roles
[cli]: https://docs.ludus.cloud/docs/using-ludus/cli
[schema]: https://docs.ludus.cloud/schemas/range-config.json
[design]: ../superpowers/specs/2026-10-23-reusable-ludus-deployment-design.md
[plan]: ../superpowers/plans/2026-10-23-reusable-ludus-deployment.md
[policy]: ../instructions/ludus-authoring.md

## Task 7 implementation documentation status (2026-10-23)

**PASS WITH WARNINGS — NOT VERIFIED.** The [usage guide](../using-ludus-deployment.md)
and [live-cycle policy](../instructions/live-debugging.md) describe the current
CLI/source implementation. Task 1 statements above retain their historical
research provenance; selected-server facts are reused evidence, not an actual
deployment/monitor invocation of the new utility.

Parent's final local validation on **2026-10-23**, using **Python 3.14.8 and
PyYAML 6.0.3**, passed all **96 tests**, compilation of all 10 selected Python
files, all four explicit-argv CLI help checks and diff checking; local-link
checking found zero broken links. Evidence:
`.superpowers/sdd/2026-10-23-reusable-ludus-deployment/final-local-validation.txt`.
These results precede this evidence-summary documentation update. Fresh review
remains parent-owned. Task 7 documentation writer performed no command or server
execution.

No live mutation, selected-history monitoring, failure/recovery path or
production-canary sanitization is verified. No deployment readiness follows
from static checks. Python >=3.11/PyYAML >=6.0,<7 is a declared target, not a
tested minimum; the Python 3.11 minimum and other allowed runtime combinations
remain unverified. Kernel-backed local locking requires a suitable POSIX host.
Monitoring deadlines include discovery and checks around observations but can
overrun an in-flight bounded CLI operation. Automatic attribution remains
unknown-only, history is metadata-only and subject to retention, and local
locking/ledger evidence cannot attest remote bytes or detect external overwrites
or server replacement. Reset after replacement remains explicit and local-only.
