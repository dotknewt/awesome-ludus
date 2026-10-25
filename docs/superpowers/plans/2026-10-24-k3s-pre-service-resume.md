# K3s pre-service resume plan

## Approved purpose

User selected non-destructive safe resume for `ludus_k3s_bootstrap` after the quoted pip argument fix. Scope remains this role on `dev1-runner`; no cleanup, range destruction, unrelated-role mutation, or automatic repeated deploy cycles.

Diagnosis: `.superpowers/sdd/2026-10-22-dev1-live/k3s-pip-diagnostics-20261024/report.md`. Architecture review: session `ses_e91c992fdffeJKrxSNN73JVK2q`.

## State contract

Publish `ludus_k3s_bootstrap_install_state` only after preflight: `fresh`, `complete`, or `resume_pre_service`. Fresh and complete preserve existing contracts. Resume requires exact marker identity, all 13 pre-service protected destinations present/verified, and exactly these four absent: `/etc/systemd/system/k3s.service`, `/etc/rancher/k3s`, `/etc/rancher/k3s/k3s.yaml`, `/var/lib/rancher/k3s`. Systemd must report not-found/inactive/dead without a fragment/drop-in/environment override. Every other partial combination fails before mutation.

Resume Python gate: trusted system Python `-I -S -B` runs a source-supplied read-only inspector. Require the expected Python 3.12 venv layout, system-site-packages setting and interpreter resolution, only local pip 24.0, no duplicate/unknown distributions, unmanaged payload or startup injection. Check pip RECORD integrity and reject ambiguous state. Do not execute/import candidate venv code before checking it. Preserve the existing deployed lock verifier and requirements bytes.

## Mutation contract

- Resume skips artifact installation entirely: no apt/download/extraction/marker rewrite/tool replacement.
- Resume does not recreate venv or recopy lock/verifier. Install only pinned hash-verified wheels into the verified venv; prevent pip destination redirection.
- Use the corrected quoted `"--only-binary=:all:"` argument.
- Verify dependency graph, exact full local lock, and imports before creating service paths. Recheck service absence immediately before that boundary.
- Preserve original complete-install convergence, readiness predicates, pins/defaults, marker schema and published outputs. No destructive operations or Docker/GitLab runner changes.

## Execution and verification

One implementation worker owns role task changes, one focused inspector, static contracts and README. Fast-generic owns scoped commands. Controller reviews artifacts and oracle reviews recovery boundaries.

1. Add source-contract regression checks; capture expected red before production edits.
2. Implement explicit state checks and bounded mutation path; guard missing stat fields and use item labels.
3. Run changed-file YAML/lint/Python syntax/source-contract checks only. No mocks, stateful fakes or whole-role validation.
4. Review exact final diff. Read-only inspector against the current actual guest may establish this guest's candidacy, not successful installation.
5. Force-upload changed role and verify actual server source, then launch one role/host-scoped deployment and monitor actual logs/status to terminal.

## Deliberate limits

Marker means ownership, not completion. A subset of installed dependencies, completed Python without service setup, or partial service-era writes remain outside this resume window and fail closed on a later invocation. No rollback/deletion or broad repair framework is added. One resumed deployment cannot establish fresh-install, complete convergence or injected-failure behavior; report these separately.
