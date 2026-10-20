# Live Ludus deployment debugging and retries

Use this workflow for operator-authorized debugging of live Ludus deployments.
It complements the static/live evidence and authorization rules in
[`ludus-authoring.md`](ludus-authoring.md) and
[`AGENTS.md`](../../AGENTS.md#behavioral-verification).

## Approval boundary

One explicit operator approval authorizes exactly one fix → upload →
`user-defined-roles` deploy → monitor cycle for the identified range and roles.
The initial cycle requires approval too. Approval is not blanket permission for
guest probes, destructive actions, unrelated roles, broader deployment flags,
or testing-mode overrides; obtain separate authorization for those actions.

If a cycle fails, stop before any further fix, upload, or redeploy. Report the
redacted error and affected host/role/task, what passed, confirmed cause versus
unknowns, and the proposed next fix or diagnostics with risks. Ask whether to
run one more cycle and wait for an explicit go-ahead. A new error is not
authorization. Repeat only after approval, one cycle at a time, until deployment
reaches a terminal successful state or the operator stops.

## One approved cycle

1. **Investigate and make the minimal fix.** Preserve safe diagnostics and
   protect credentials: use `no_log` where secrets may appear and do not expose
   passwords, tokens, or other sensitive values in reports. Use named,
   non-secret diagnostics where possible. For role changes, pass the mandated
   scoped `ansible-validation` gate in
   [`ludus-authoring.md`](ludus-authoring.md#verification-and-evidence) before
   uploading. Validation is not live verification.
2. **Upload only changed, validated role(s).** The directory basename must be
   the exact installed namespaced role identity (for example,
   `dotknewt.ludus_splunk_collector`), not merely the source directory name.
   Verify the role identity and uploaded content where possible. The CLI form
   is:

   ```sh
   ludus ansible role add -d <directory-with-exact-role-name> -f
   ```

3. **Deploy only the authorized role phase** for the approved range:

   ```sh
   ludus range deploy -r <range-id> -t user-defined-roles
   ```

   `dev` may be used as an example range ID. Do not add broader flags or
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
   reporting success. Report any remaining fresh-bootstrap or convergence gaps
   separately. If terminal failure occurs, use the stop-and-ask process above.

## Approval request after failure

Include only redacted, relevant evidence and ask a clear yes/no question. For
example:

> The approved cycle for `<range-id>` / `<role identity>` failed at
> `<host>/<role>/<task>`. Error: `<redacted relevant error>`. Passed:
> `<verified steps>`. Cause: `<confirmed cause>`; unknowns: `<unknowns>`.
> Proposed next cycle: `<minimal fix or diagnostics>`. Risks/scope:
> `<impact and authorized roles>`. Do you approve one additional
> fix-upload-deploy-monitor cycle for this range and role?

Do not proceed until the operator answers affirmatively.

## References

- [Ludus roles](https://docs.ludus.cloud/docs/using-ludus/roles)
- [Ludus CLI](https://docs.ludus.cloud/docs/cli)
- [Repository Ludus authoring and verification policy](ludus-authoring.md)
