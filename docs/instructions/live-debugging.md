# Live Ludus deployment debugging and retries

Use this workflow for one explicitly requested **observed** live cycle, including
`/live RANGE roles` or `/live RANGE full`. It complements the
[authoring policy](ludus-authoring.md) and [behavioral verification rules](../../AGENTS.md#behavioral-verification).
The reusable utility's ordinary `deploy` command remains launch-only.

## Approval and scope

One request authorizes one preflight → changed configured-role uploads → server
presence verification → launch → explicit observation → report cycle. Start with
existing changes; no new fix or duplicate approval is required for the approved
cycle. Use [the utility](../using-ludus-deployment.md), not ad hoc scripts or
direct-command substitutes. If it cannot satisfy a requirement, stop and ask.

`roles` authorizes upload of the range-wide changed/unknown configured-role set
and deployment of the entire `user-defined-roles` phase. It does **not** select
individual roles. `full` explicitly authorizes all deployment phases, with the
same changed-role upload selection. Role replacements are user-scoped and can
affect other ranges using those identities.

For an older invocation naming particular changed roles, do not silently upload
other configured roles or pretend the phase is a named-role filter. Clarify and
obtain authorization for the utility's range-wide changed set before invoking.
Missing range/scope requires clarification. `--force-upload` replaces all
configured roles and needs authorization for that set; it is not required for
ordinary changed uploads, which already use forced replacement internally.

Approval excludes additional cycles, guest probes, destructive setup/cleanup,
failure injection, unrelated role changes, broader flags and testing overrides.
Each needs its own authorization. A destroyed range blocks roles scope before
uploads: ask for explicit full scope, never widen it automatically.

## One requested cycle

1. **Confirm target, scope and local source checkout.** Follow the setup and
   source-resolution rules in the [usage guide](../using-ludus-deployment.md).
   Use existing secure environment injection for `LUDUS_API_KEY`; never print
   credentials. All configured sources must resolve before any upload.
2. **Invoke deploy once**, substituting the approved range and scope:

   ```sh
   python scripts/ludus_deploy.py deploy --range RANGE --scope roles
   ```

   Use `--scope full` only when explicitly requested. The utility stages and
   hashes sources, force-replaces selected changed/unknown roles, checks exact
   structured responses and installed user-role presence, and rechecks the
   config/status before one launch. Presence does not attest uploaded bytes.
   Record sanitized output, run ID, evidence path and launch disposition.
3. **Observe without guessing attribution.** If a run ID exists, use:

   ```sh
   python scripts/ludus_deploy.py monitor --run RUN_ID
   ```

   This may identify candidates but cannot bind them to the launch. If
   attribution is unknown, stop/report and ask the user to explicitly select
   an ID; never pick the newest or a timestamp-near candidate. With an explicitly
   approved history ID, continue the same cycle's read-only observation:

   ```sh
   python scripts/ludus_deploy.py monitor --range RANGE --history-id ID --wait --timeout 10800
   ```

   Selection reports only that record's outcome, not launch provenance.
   Metadata-only monitoring cannot establish a specific task fix or sanitized
   production output. Additional diagnostic/log or guest evidence requires
   appropriate authorization. Missing/pruned IDs, interrupted observation and
   timeout remain unknown. Timeout includes deadline checks but may overrun an
   in-flight bounded CLI operation; never redeploy because observation timed out.
4. **Report and stop.** Separate static evidence, reused evidence, launch
   acceptance, selected-record outcome and unresolved launch attribution.
   Report what is actually known, fresh-bootstrap/convergence gaps and any
   unavailable task-level evidence. On failure/unknown, report sanitized
   diagnostics, affected host/role/task only when known, confirmed cause versus
   unknowns, and proposed next diagnostics/fix with risks. Do not perform another
   fix, upload or deploy until separately requested/approved. Keep private
   recovery evidence; do not automatically resume mutations or clean up external
   resources.

## References

- [Pinned official-source research and compatibility limits](../research/reusable-ludus-deployment-compatibility.md)
- [Utility usage and exit codes](../using-ludus-deployment.md)
- [Repository Ludus authoring and verification policy](ludus-authoring.md)
