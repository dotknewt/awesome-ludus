---
description: Run one requested live Ludus debugging cycle
agent: build
model: openai/gpt-6.1-sol#low
---

Run the live Ludus deployment debugging workflow for range `$1` and scope `$2`.
`$2` must be either the changed role name(s) or the literal `full` to deploy
the complete range rather than only user-defined roles.

The `/live` invocation with both arguments is the user's authorization for this
one cycle; do not ask for duplicate approval. Ask for any missing range or scope
arguments rather than guessing. Treat `full` as the requested broader deployment
scope, and do not skip force-uploading and server-side verification of changed
roles before deploying.
Read and follow `docs/instructions/live-debugging.md` as the authoritative
workflow, including its scope boundaries and failure handling.
