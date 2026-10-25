# Repository instructions

## Ludus skill documentation accuracy

When reviewing, adding, or creating Ludus skills, follow [the official documentation verification instructions](docs/instructions/ludus-skill-documentation.md). Verify factual guidance against current official Ludus documentation before completing the work.

## Ludus artifact authoring and review

When authoring or reviewing Ludus sources, blueprints, range configs, or roles, follow the mandatory [Ludus authoring policy](docs/instructions/ludus-authoring.md). It distinguishes repository policy from official behavior and defines verification and evidence requirements.

# Project workflow

## Live deployment debugging and retries

- For live Ludus deployment debugging or retries, read and follow [`docs/instructions/live-debugging.md`](docs/instructions/live-debugging.md).

## Router state and recovery

- Read the active session's router head once on entry or recovery, then use the cached result. A repeated reminder alone is not evidence of a state change.
- Refresh only after a known external update, a restart, or an observed contradiction. After your own successful patch, use the resulting state without a verification reread.
- If an identical read returns unchanged content, take the next substantive action or await the completion hook; stop the read loop.
- After a restart, reconcile existing child IDs and saved results before resuming unfinished work. Reuse completed evidence; preserve interrupted edits and resume the original session.
- Keep recovery state concise and durable: current phase, exact next action,
  blockers, active child/monitor IDs and terminal state, and whether the latest
  cycle's authorization was consumed. Keep historical entries in the ledger,
  not the router head; update terminal closure once observed. Persist
  non-sensitive, repository-permitted evidence manifests (commands, exits,
  hashes, artifact locations) in an ignored durable workspace, not only `/tmp`.
  Never commit external credentials or raw private configuration. If evidence
  is lost, mark it unavailable; do not recreate claims.

## Behavioral verification

- Before parallel role implementation, check shared input/output shapes, ownership, and failure semantics against the project's approved contracts. Resolve incompatible interfaces before dispatch.
- For Ludus roles, follow the static-and-live-only verification policy in `docs/instructions/ludus-authoring.md`; simulations and stateful fakes are not verification evidence.
- When authorized, exercise the actual role entrypoint for fresh installation, convergence, and relevant failure paths. For cleanup and credential lifecycles, verify failures before and after mutation and the resulting service state, credential disposition, authoritative markers, and preservation of unrelated resources.
- Verify sanitization using representative canary-bearing events through production processing. Rendered configuration alone does not prove sanitized output.
- Report separately what static and live verification was executed, what evidence was reused, and what remains unverified. Static evidence does not establish selected-version compatibility or deployment readiness.
- Reuse validation only while the reviewed artifact and relevant dependencies remain unchanged. Record a scoped diff and exact evidence provenance for each re-review.
- Batch scoped checks under one owner; reuse evidence only with valid hash,
  environment, and dependency scope. The controller centrally finalizes report
  status; do not spawn docs-only report-correction rounds or retest unchanged
  files. Real code fixes still receive proportionate review.
- Live deployment, guest probes, and destructive cleanup require their own authorization; verification gaps do not authorize those actions.
