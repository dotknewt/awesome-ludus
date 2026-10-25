# Live Ludus deployment debugging and retries

Use this workflow for a live Ludus deployment or retry explicitly requested by
the user, or invoked with `/live` and a range and scope. That request authorizes
the one requested cycle below.
It complements the static/live evidence and authorization rules in
[`ludus-authoring.md`](ludus-authoring.md) and
[`AGENTS.md`](../../AGENTS.md#behavioral-verification).

## Approval boundary

One explicit live/deploy request or `/live` invocation with a range and scope
authorizes exactly one force-upload → server verification → deploy → monitor →
report cycle for the identified range and deployment scope.
The scope may be the changed role(s), deployed with `user-defined-roles`, or
`full`, deployed for the complete range. Start with the existing changes; a new
fix is not a required first step. Do not ask for duplicate approval for the
requested cycle.
Approval is not blanket permission for
guest probes, destructive actions, unrelated roles, broader deployment flags,
or testing-mode overrides; obtain separate authorization for those actions.

If a cycle fails, stop before any further fix, upload, or redeploy. Report the
redacted error and affected host/role/task, what passed, confirmed cause versus
unknowns, and the proposed next fix or diagnostics with risks. The request
authorizes only its requested cycle; wait for an explicit request or approval
before another fix, upload, or deploy. Do not ask for duplicate approval to
perform a cycle already explicitly requested.

## One requested cycle

1. **Force-upload only changed role(s).** The directory basename must be
   the exact installed namespaced role identity (for example,
   `dotknewt.ludus_splunk_collector`), not merely the source directory name.
   Use the CLI form:

   ```sh
   ludus ansible role add -d <directory-with-exact-role-name> -f
   ```

   The `--force`/`-f` flag is mandatory when uploading an updated role: without
   it the server retains the already-installed role version instead of
   overwriting it, so a subsequent deploy can silently run old role content.
   Never upload an update without it.

2. **Verify the server has each changed role** with `ludus ansible role list`
   and confirm that the installed identity/version (and uploaded content, where
    the output permits) is the changed role. Do not treat a successful upload
    command alone as proof that the server has the intended role update.

    When an authorized controller transport is available, compare SHA-256 hashes
    of changed runtime files locally and at the actual remote installed role path.
    Record the transport/host, installed identity, paths, hashes and command exits.
    A local path resembling a server path is not remote evidence. If byte-level
    verification is unavailable, record that gap rather than equating catalog
    presence with uploaded content. This step does not grant new SSH access.

3. **Deploy the requested scope** for the requested range. For changed roles
   only:

   ```sh
   ludus range deploy -r <range-id> -t user-defined-roles
   ```

   For the complete range, when `full` was explicitly requested:

    ```sh
    ludus range deploy -r <range-id>
    ```

   `full` does not remove the changed-role upload and server verification
   requirements above. It means the deploy is not restricted to the changed
   roles; it may run all configured deployment phases.

   `dev` may be used as an example range ID. Do not add other broader flags or
   testing-mode overrides without approval. A successful command launch does
   not mean deployment completed.
4. **Monitor the actual deployment** until terminal status using both logs and
   range status:

   ```sh
   ludus range logs -r <range-id> -f
   ludus range status -r <range-id> --json
   ```

   An observation timeout is unknown, not terminal success or failure; never
   redeploy solely because monitoring timed out. Establish the result from the
    deployment recap/status and confirm the actual fixed task passed before
    reporting success.
    Preserve host/task result rows, not only task headings: a heading can precede
    a skipped task. Keep repeated task occurrences distinct and missing results
    unknown. For protected failures, capture the actual allowlisted diagnostic
    object, including multiline JSON; a schema-validation receipt is not the
    report. Use [local evidence capture](#local-evidence-capture) for supported
    default-callback output without storing raw logs.
5. **Report the result.** Separate any static validation from live evidence,
   state what passed and what remains unknown, and identify any remaining
   fresh-bootstrap or convergence gaps. If terminal failure occurs, diagnose
   from the available authorized evidence and propose the next fix or
   diagnostics using the stop-and-wait-for-next-request rule above. Do not make
   another fix before that request or approval.

## Local evidence capture

`scripts/collect_deployment_evidence.py` is a local, read-only parser. It does not
invoke Ludus, SSH, or deployment commands. Supply a private JSON status snapshot,
the expected range and deployment timestamp, and a reviewed allowlist of exact
host/task names. The status snapshot uses Ludus's `rangeID`, `lastDeployment` and
`rangeState` fields; unrelated fields are excluded from the resulting evidence.
The initial supported states are the observed `SUCCESS`, `ERROR`, and `DEPLOYING`;
other states produce a fixed input error. Fractional UTC deployment timestamps
are supported. This is not a claim to support every Ludus state or callback.

The allowlist is a trusted input, not something to generate blindly from logs:

```json
{
  "hosts": ["dev1-runner"],
  "tasks": [
    "splunk_container_logs : Apply only a real reviewed Helm diff with bounded wait",
    "splunk_container_logs : Publish only the safe Helm failure report"
  ]
}
```

For an already-authorized run, after obtaining its status snapshot, pipe logs
directly to the collector instead of saving raw output. Use a new output directory:

```sh
umask 077
set -o pipefail
mkdir -p .superpowers/evidence
ludus range logs -r "$RANGE" 2>/dev/null |
  python3 scripts/collect_deployment_evidence.py \
    --range "$RANGE" --deployment "$LAST_DEPLOYMENT" \
    --status status.json --allowlist evidence-allowlist.json \
    --output .superpowers/evidence/new-capture
```

Check both commands' exit status through the pipeline; the parser cannot attest
to upstream transport success. It supports the observed Ansible default callback,
not arbitrary callback formats. Raw input is never copied to artifacts or parser
errors. Only recognized fixed diagnostic schemas and allowlisted outcomes are
retained. Keep raw upstream errors out of shared transcripts too.

The collector writes private `evidence.json`, verifies readback, and refuses an
existing output directory or symlink path. Exit `0` means complete capture,
`3` means safely persisted incomplete evidence, and `2` means an input/output
error. A failed deployment can have a complete capture. Missing optional failure
diagnostics after success is normal. Inspect the recorded issues and unknown
outcomes before drawing conclusions.

The allowlist selects evidence; it is not a required-task checklist. Recognized
events outside it are intentionally filtered. A recap-only capture can be complete
without establishing that a selected task ran. Check the retained task outcomes
for the behavior being claimed. Rescued or ignored failures remain failed task
observations but do not by themselves contradict a successful terminal recap.

A matching status timestamp identifies the selected status observation; it does
not prove that an arbitrary supplied log stream belongs to that run. Preserve the
collector's attribution limitation and corroborate log/run identity through the
authorized monitor. Neither successful capture nor deployment proves ingestion,
fresh installation, convergence, or independent readiness checks.

## Module provenance during diagnosis

For a suspected collection/API mismatch, record one coherent provenance tuple:

- Resolved FQCN, module path and realpath from the relevant loader context.
- Namespace, name and version from the manifest at that resolved collection root,
  plus the resolved module's SHA-256; do not pair it with another installation.
- Account, relevant collection search context, observation time and deployment ID,
  excluding credentials and full environment/config dumps.
- Evidence type: actual executed-module record, current loader query, or
  post-failure loader snapshot. A rescue task can run in another worker; its
  lookup is not a trace of the failed worker's executed payload.

Keep a suspected unsupported parameter as a hypothesis until the protected error
classification or execution evidence establishes it. A supported-parameter list
mentioning a name is not evidence that the name was rejected. Prefer the existing
role's fixed safe diagnostic report over exposing raw module results.

## Pinned dependency compatibility

Before correcting a chart or vendor-config failure, compare the exact pinned
artifact's schema, merged defaults, same-version examples, and activation/template
conditions together. Record source ref or archive checksum provenance. Explicit
`false`, omission, and `null` can have different schema, merge and runtime effects;
a default flag alone does not establish whether its destination is active.

Trace the incompatible field back to the role template and any matching artifact
contract. Propose the smallest correction that preserves security, ownership and
the intended telemetry scope. Keep schema validation enabled. Treat source/schema
checks as static evidence; runtime claims require the separately authorized real
entrypoint. Do not add a deployment merely to fill an evidence gap.

## References

- [Ludus roles](https://docs.ludus.cloud/docs/using-ludus/roles)
- [Ludus CLI](https://docs.ludus.cloud/docs/cli)
- [Repository Ludus authoring and verification policy](ludus-authoring.md)
