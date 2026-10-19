# Project workflow

## Router state and recovery

- Read the active session's router head once on entry or recovery, then use the cached result. A repeated reminder alone is not evidence of a state change.
- Refresh only after a known external update, a restart, or an observed contradiction. After your own successful patch, use the resulting state without a verification reread.
- If an identical read returns unchanged content, take the next substantive action or await the completion hook; stop the read loop.
- After a restart, reconcile existing child IDs and saved results before resuming unfinished work. Reuse completed evidence; preserve interrupted edits and resume the original session.

## Behavioral verification

- Before parallel role implementation, check shared input/output shapes, ownership, and failure semantics against the project's approved contracts. Resolve incompatible interfaces before dispatch.
- Exercise the actual role entrypoint for fresh installation, convergence, and relevant failure paths; task-include tests supplement rather than replace entrypoint coverage.
- Stateful fakes must reject impossible transitions: starting a missing unit, using the wrong user/HOME/context, reading inaccessible sources, or executing an unextracted archive. Derive responses from modeled state rather than unconditional success.
- For cleanup and credential lifecycles, inject failures before and after mutation; assert final service state, credential disposition, authoritative markers, and preservation of unrelated resources.
- Sanitization tests must feed representative canary-bearing events through production processing or explicitly identify a model-only approximation. Rendered configuration alone does not prove sanitized output.
- Report separately what was executed, what was simulated, what evidence was reused, and what remains unverified. Offline tests do not establish selected-version compatibility or deployment readiness.
- Reuse validation only while the reviewed artifact and relevant dependencies remain unchanged. Record a scoped diff and exact evidence provenance for each re-review.
- Live deployment, guest probes, and destructive cleanup require their own authorization; verification gaps do not authorize those actions.
