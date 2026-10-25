# Audit Order Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair only the recorded owned audit ordering failure without rewriting CSV or weakening fail-closed guards.

**Architecture:** Keep strict parsing separate from private tokenization. A deep recovery entrypoint proves immutable intent and admits only the four recorded states, journals its successor before mutation, then commits after strict readback under the existing lock.

**Tech Stack:** Windows PowerShell 5.1, DirectoryServices.Protocols, GroupPolicy, protected JSON state.

**Spec:** ../specs/2026-10-23-audit-order-recovery-design.md

## Global Constraints

- State schema_version 1; order_recovery schema_version 1, kind audit_extension_order, exact keys only.
- Preserve original intent, CSV and raw foreign tuple bytes; R=NextVersion(V), observed 9→10.
- No guest writes/probes/upload/deploy, dependencies, commits or synthetic runtime tests during implementation.
- Existing no-reparse/ACL/identity/version/ownership guards and prior fixes remain intact.

## Review Focus

- Mixed or advanced versions: recovery must reject before mutation (Task 2 static transition review; live fault path unverified).
- Changed desired audit configuration or foreign bytes: exact set/setting/hash proof rejects (Task 2 source guard review).
- State write succeeds but acknowledgement fails: retained journal supports only recorded transition, never rollback (Task 2 durability review).
- Check/WhatIf with pending: no write or normal reconciliation, no completion claim (Task 3 control-flow review).
- Old binary sees new journal: rejects unsupported key; README prohibits rollback while pending (Task 3 documentation review).

### Task 1: Canonicalization and narrow state admission

Files: files/Publish-LoggingAudit.ps1, files/LoggingPolicyState.ps1 under ansible/roles/windows_logging_policy.

Interfaces: private Split-LoggingAuditExtensionTuples(string)->tuple[]; strict ConvertFrom-LoggingAuditExtensions(string)->tuple[]; Get-LoggingAuditIntendedExtensions(string,bool)->string; Get-LoggingPolicyContext(Configuration,AllowAuditOrderRecovery=false)->hashtable.

- [x] Snapshot existing scoped files/hashes; reuse actual production failure and captured state as red evidence.
- [x] Extract tokenizer; sort typed CSE keys with shared ordinal-ignore-case comparer and strict output validation.
- [x] Validate optional exact recovery journal and admit only one eligible logging pending while retaining existing checks.
- [x] Review grammar, duplicate, ordering and default-deny preservation in scoped diff.

### Task 2: Deep guarded recovery

File: files/Publish-LoggingAudit.ps1.

Interface: Resume-LoggingAuditOrderRecovery(Context,Configuration,PlanOnly)->{changed,completed}; shared Set-LoggingAuditContext(Context,Configuration) derives GPO paths.

- [x] Implement original-intent ordering proof and exact GUID/configuration/CSV checks.
- [x] Read low-level LDAP/GPT/payload without weakening normal strict snapshots; classify only four approved states.
- [x] Revalidate complete protected state/identity and allowed observations before writes; clone/persist journal, LDAP then GPT, strict readback and clone/commit.
- [x] Expose phase/version/GUID/hash diagnostics; leave exceptions and uncertain writes pending.
- [x] Source-review each transition, changed-state rejection and state-reference swap. No fake state-machine tests.

### Task 3: Entrypoint, operating contract and gate evidence

Files: files/Invoke-LoggingPolicy.ps1 and README.md.

- [x] Opt in internally, recover under writer lock before normal reconciliation, share context path derivation, return early for check/WhatIf.
- [x] Document exact supported recovery, no manual concurrent edits, old-binary rollback restriction and unverified paths.
- [x] Run scoped diff/whitespace checks and capture before/after hashes/diff; report native syntax/runtime limitations. Parent owns independent review and changed-file-only static validation.

## Self-review

All eight approved design sections map to Tasks 1–3. Signatures and ownership boundaries are consistent; recovery mutates only after full proof and never handles other pending variants. Verification is static/live only: review-focus cases are explicit source-review obligations, not claims of tested failure behavior. No extra review/approval question is needed; user already approved the concrete design and specialist execution. No commits.
