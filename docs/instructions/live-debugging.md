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
5. **Report the result.** Separate any static validation from live evidence,
   state what passed and what remains unknown, and identify any remaining
   fresh-bootstrap or convergence gaps. If terminal failure occurs, diagnose
   from the available authorized evidence and propose the next fix or
   diagnostics using the stop-and-wait-for-next-request rule above. Do not make
   another fix before that request or approval.

## References

- [Ludus roles](https://docs.ludus.cloud/docs/using-ludus/roles)
- [Ludus CLI](https://docs.ludus.cloud/docs/cli)
- [Repository Ludus authoring and verification policy](ludus-authoring.md)
