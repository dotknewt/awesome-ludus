# Reusable Ludus deployment utility

Use `scripts/ludus_deploy.py` to upload changed configured roles and request one
deployment, or to observe an explicitly selected history record. Deployment is
**launch-only**: acceptance does not mean completion. Agents must reuse this
utility; if a requirement is unsupported, stop and ask rather than inventing a
replacement script or bypassing its checks.

## Setup

Requires Git, a POSIX host with kernel file locking, Python **>=3.11**, PyYAML
**>=6.0,<7**, and `ludus` on PATH. The supported client/server pair is pinned to
**`2.3.10+fccf931e`**; other or missing versions block. From your checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r scripts/requirements-ludus-deploy.txt
python scripts/ludus_deploy.py --help
```

Supply `LUDUS_API_KEY` in the process environment through your existing secure
credential mechanism. Do not echo it, place it in command arguments or shell
history, or copy it into evidence. Keyring-only credentials are unsupported:
arrange secure environment injection before invoking the utility. ROOT and
impersonation are unsupported; nonempty ambient user overrides block.

No endpoint registration is required. The utility resolves ambient Ludus
endpoint, proxy and certificate-verification settings once, authenticates range
and role reads, and freezes that context privately for the operation. Secrets
are not persisted or passed in argv; this is not a guarantee of Python memory
zeroization. See the [pinned source research and transport contract](research/reusable-ludus-deployment-compatibility.md).

## Choose sources and scope before launching

Role sources come from the Git checkout/worktree containing the **current
working directory**, never the script's installation path. `--checkout PATH`
explicitly selects another checkout. The server's active range config determines
the required role set; a local blueprint is not substituted.

Each configured identity first resolves to its exact directory basename under
`ansible/roles/`. For example, `example.web` needs `ansible/roles/example.web`,
or an explicit mapping in `ansible/role-identities.yml`:

```yaml
schema_version: 1
roles:
  example.web: web
```

Mapping paths are relative to `ansible/roles/`. Check the mapping into the source
repository. A conflicting exact directory, duplicate/ambiguous mapping, unsafe
path, unsupported dynamic reference, or missing dependency blocks. Metadata
`galaxy_info.author` and `role_name` must be nonempty, but do not rename the
installed role. Namespace guessing and suffix matching are not supported.
All required roles must resolve locally before any upload, even if installed
remotely; missing-role diagnostics list the missing configured identities and
search root when safe to display.

Private staging includes uncommitted and untracked uploadable content (even
gitignored content), excluding `.git`, `__pycache__`, and `*.pyc`. Symlinks and
special files are rejected. Content manifests hash the staged bytes, rather
than relying on Git revision alone.

Replace `RANGE` below with the approved range. Execute only the requested choice:

```sh
python scripts/ludus_deploy.py deploy --range RANGE
```

Default `--scope roles` launches the range's `user-defined-roles` phase, **not a
named-role subset**. Upload selection covers every changed/unknown configured
role (including missing local history or user-role presence). The caller must
authorize this range-wide changed set. A request limited to named roles does
not silently authorize other uploads; resolve that mismatch before invoking.
Uploads replace authenticated-user roles and can affect other ranges using
the same identities.

For an explicitly approved full deployment:

```sh
python scripts/ludus_deploy.py deploy --range RANGE --scope full
```

`DESTROYED` with roles scope blocks **before uploads**; it never upgrades itself
to full. Busy, testing, unsupported state, invalid config and unresolved source
checks also block. Full still performs the same source/upload checks.
`--force-upload` uploads **all resolved configured roles**, not just changed
ones; use only when that replacement set is approved. It bypasses no preflight.
There is no named-role filter, deploy-force, impersonation or testing override.

Each selected upload uses the pinned client's forced replacement operation.
The adapter exposes only sanitized `UploadResult` disposition/messages, checks
the exact structured success response and verifies user-scoped role presence
before updating history. Exit zero or role presence alone does not attest bytes.
Partial/ambiguous uploads stop the workflow. Config/status/presence are checked
again before the **single** launch invocation. Unknown acceptance never triggers
retry; even an unchanged upload set still requests one deployment.

## Observe explicitly

Accepted launch output includes a local run ID and evidence directory:

```sh
python scripts/ludus_deploy.py monitor --run RUN_ID
```

This performs read-only observation, checks the saved target, and may report
candidate history IDs. Attribution remains **unknown**: the pinned launch
response has no authoritative history binding. Never automatically choose the
newest record, infer a match from timestamps, or treat a candidate as completion.

Once the user explicitly selects a history ID:

```sh
python scripts/ludus_deploy.py monitor --range RANGE --history-id ID
python scripts/ludus_deploy.py monitor --range RANGE --history-id ID --wait --timeout 10800
```

These are alternative one-shot/wait observations. Selected-history success
reports only that record's result, not provenance of a utility launch. `success`
is terminal success; `failure` and `aborted` are terminal failure. `running` is
nonterminal. Missing/pruned/duplicate IDs, unsupported metadata, lost access or
interruption remain unknown; a newer deployment never replaces the selection.
Only history metadata is read, not raw logs or task recaps, so this cannot prove
that a particular repaired task or production sanitization path passed.

Default observation is one-shot. `--wait` polls reads, with `--interval 30` and
`--timeout 10800` defaults (positive finite seconds). The deadline includes
discovery and is checked around observations; it is not a hard wall-clock kill.
An in-flight bounded CLI operation can overrun it. Waiting on `--run` cannot
create attribution and will still remain unknown. Timeout never authorizes
redeployment.

| Exit | Meaning |
| --- | --- |
| 0 | Launch accepted (completion unobserved), selected record succeeded, or local reset succeeded; read the command/outcome. |
| 2 | Invalid arguments, blocked preflight, or unavailable/busy local state. |
| 3 | Known upload denial or launch rejection. |
| 4 | Unknown/ambiguous outcome; can also accompany known acceptance with uncertain local evidence. |
| 5 | Explicitly selected history record failed or was aborted. |

## Shared history, recovery and retention

State defaults to `~/.local/state/awesome-ludus` (or
`$XDG_STATE_HOME/awesome-ludus`), shared across checkouts. Private directories and
files retain run/observation evidence and a hash-based upload ledger. Keys use
the exact credential-free endpoint, authenticated user and role identity, not
range. Endpoint aliases are not merged. One global local mutation lock spans
all keys; an upload invalidates same-role entries across other endpoint/user
keys conservatively. Lock contention blocks; never steal a live lock.

This coordinates only processes sharing that state root. External overwrites,
other machines/state roots and server replacement are not automatically
detected. Presence is not remote-content attestation. After server replacement
or restore, explicitly reset before trusting the old ledger; after external
role replacement, invalidate stale history or explicitly authorize force-upload:

```sh
python scripts/ludus_deploy.py reset-upload-history
```

Reset is local-only, needs no credentials or server calls, and invalidates all
upload entries under the global lock while preserving run/observation evidence.
It neither deploys nor deletes remote roles/resources.

Interrupted/in-flight uploads remain unknown on recovery. No mutation is
automatically resumed. Retain private evidence for diagnosis; inspect the
reported run/observation IDs before deciding on another separately authorized
cycle. Normal exit attempts local staging cleanup; a crash may leave private
staging behind. There is no automatic evidence-retention purge or external
resource cleanup. Review retained staged content as sensitive before any manual
local cleanup; do not remove active state/locks or discard recovery evidence.

## Verification boundary

**PASS WITH WARNINGS — NOT VERIFIED.** Parent's final local validation on
2026-10-23 passed all 96 tests, compilation of all 10 selected Python files,
all four explicit-argv CLI help checks, and diff checking; local-link checking
found zero broken links. Runtime: Python 3.14.8 and PyYAML 6.0.3. Evidence:
`.superpowers/sdd/2026-10-23-reusable-ludus-deployment/final-local-validation.txt`.
These results precede this evidence-summary documentation update; fresh review
remains parent-owned.
Selected-server read-only facts are reused Task 1 evidence, not execution of
this utility. No live upload, deployment, monitoring, failure/recovery or
production-canary sanitization has been verified. Python 3.11 minimum and other
allowed runtime versions remain untested. See [compatibility evidence](research/reusable-ludus-deployment-compatibility.md)
and [authoring policy](instructions/ludus-authoring.md).

For one explicitly requested observed cycle, follow
[`/live` policy](instructions/live-debugging.md); unsupported requirements need
discussion, not an automatic fallback script or broader flags.
