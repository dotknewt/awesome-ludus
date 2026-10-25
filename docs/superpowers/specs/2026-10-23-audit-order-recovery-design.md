# Guarded audit extension ordering recovery

Approved 2026-10-23. Scope: windows_logging_policy only; implementation precedes independent review/static validation. One full deployment is reserved after that gate. No manual GPO, registry, CSV or protected-state edits.

## Ordering contract

Separate a private grammar/duplicate-validating tokenizer from the strict public extension parser. Both canonical generation and sortedness validation use StringComparer.OrdinalIgnoreCase over actual CSE string keys, never hashtable property sorting. Preserve each unrelated raw tuple byte-for-byte; validate generated output with the strict parser.

## Durable intent

Keep state schema_version 1. Only logging/audit_publish pending may add optional `order_recovery`, with exact keys: schema_version=1, kind=audit_extension_order, intended_machine_extensions=Egood, intended_ad_version=R, intended_gpt_version=R. Preserve original target, prior/intended ownership and audit fields unchanged. Recompute Egood from the strict original prior extensions and R=Get-LoggingAuditNextVersion(V), where V is original intended version (observed 9→10). Validate the recorded journal against those recomputed values. Old binaries reject the added key; rollback is unsupported while pending.

## Admission and proof

Context has an internal default-false AllowAuditOrderRecovery option. Admit only a single logging/audit_publish pending, logging enabled; retain protected ACL/no-reparse, domain, writer, selected DC, configured name, marker, GUID and unambiguous ownership checks. Admission grants no mutation permission. Recovery runs under the existing writer lock before any object/registry/audit/link reconciliation. Normal publisher still rejects pending state.

Require committed audit GUIDs equal prior ownership; target GUID set equals intended ownership; no retirement; current requested GUIDs/settings equal intended ownership and exactly one matching actual system-subcategory row per GUID. Strict CSV grammar/hash remains mandatory; unrelated valid rows are preserved, not adopted. Prior versions agree; V is NextVersion(prior); desired deletion is false and hash nonnull. Domain gPCFileSysPath is validated independently of selected-DC SYSVOL paths.

Strictly parse prior extensions and compute expected canonical publication Egood. Tokenize original intended Ebad without weakening the public parser; require identical CSE sets and ordinal raw tuple bytes to Egood, including expected audit tool. Ebad must differ and violate ordering.

## Allowed transitions

All require identical payload and full ownership/identity proof:

| Journal | AD/GPT/extensions | Only allowed action |
|---|---|---|
| absent | V/V/Ebad | Persist successor journal atomically |
| present | V/V/Ebad | Combined LDAP version R/extensions Egood update |
| present | R/V/Egood | GPT-only update to R |
| present | R/R/Egood | Strict final readback then ownership/state commit |

Everything else fails closed, including unjournaled canonical data, changed configuration, malformed/duplicate tuples, unexpected versions or payload. Resume uses recorded R, not current-version increment.

## Write discipline

Clone candidate state; persist journal through the existing atomic writer/readback before LDAP. Recheck identity, protected on-disk pending and exact allowed state immediately before each mutation and after LDAP before GPT. Never rewrite audit.csv. Exceptions/timeouts leave durable intent; no rollback/cleanup catch. Strict final readback checks original payload hash and R/Egood, then identity/pending are revalidated and original intended ownership is atomically committed with pending cleared. Swap caller state only after successful persistence. Check/WhatIf reads/reports, writes nothing and returns before normal reconciliation without claiming completion.

Progress records original/recovery versions, GUID/hash and each phase/outcome. Existing mutex is local-writer exclusion, not distributed CAS; no concurrent manual GPO edits is a prerequisite. Observed external changes stop recovery.

## Verification boundary

Existing real native capture is red evidence: publisher output violates its parser; actual V/V/Ebad and CSV match pending. Static/source review only during implementation; no mocks or simulations. Native local PowerShell unavailable. Parent independently reviews and validates changed files before live role recovery. Crash-resume/fault injection and a second convergence run are not authorized and remain unverified.
