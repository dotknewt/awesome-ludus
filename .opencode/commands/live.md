---
description: Run one requested live Ludus debugging cycle
agent: build
model: openai/gpt-6.1-sol#low
---

Run the live Ludus deployment debugging workflow for range `$1` and scope `$2`.
`$2` must be `roles` (the range's user-defined-roles phase) or `full`
(all deployment phases). Both authorize the range-wide changed/unknown
configured-role upload set, not a named-role subset. If the caller supplies
individual role names, clarify this scope mismatch before invoking the utility;
never silently upload other roles under a subset-only request.

The `/live` invocation with both arguments is the user's authorization for this
one cycle; do not ask for duplicate approval. Ask for any missing range or scope
arguments rather than guessing. Reuse `scripts/ludus_deploy.py deploy` exactly
once with the approved range/scope; it force-replaces selected changed roles
and verifies server presence. `--force-upload` means all configured roles and
requires authorization for that set. Do not invent scripts or bypass unsupported
requirements; stop and ask instead.
Then use the utility's read-only monitor. `--run` yields unknown attribution and
possible candidates: stop/report and ask for explicit history-ID selection,
never automatically choose the newest. Monitor an explicitly approved ID with
`--range RANGE --history-id ID --wait`; its outcome is not launch provenance.
No automatic retry, broader flags, guest probes or external cleanup is authorized.
Read and follow `docs/instructions/live-debugging.md` as the authoritative
workflow, including its scope boundaries and failure handling.
