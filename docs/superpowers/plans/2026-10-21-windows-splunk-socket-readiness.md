# SUPERSEDED — Windows Splunk socket readiness plan

> The former native AF_UNIX/curl socket-repair plan is abandoned and was not
> implemented. User-approved replacement scope: remove mandatory Windows
> administrator API authentication and whole-installation filesystem/reparse
> scans. Do not add a socket client, curl dependency, listener, or ACL policy.

# Windows Splunk readiness simplification plan

> **For agentic workers:** Use the implementation specialist after parent review. Steps use checkbox syntax; tests precede production changes.

**Goal:** Make Windows role readiness represent managed installation, configuration, service, and bootstrap metadata without requiring administrator login or scanning unrelated filesystem trees.

**Architecture:** Replace broad recursive filesystem scans with bounded checks for role-managed paths and their ancestors, preserving config-conflict classification while preventing reads through unvalidated reparse directories. After service start, wait boundedly for a nonempty regular `etc/passwd`; do not read or authenticate credentials.

**Tech Stack:** Ansible YAML, PowerShell 5.1, existing Windows role tasks, Python static source-contract tests.

**Spec:** User-approved simplification in the current request and checklist `/tmp/opencode/splunk-windows-simplification/plan.md`; current implementation context is `tasks/windows/inspect.yml`, `configure.yml`, and `install.yml`.

## Global constraints

- No live guest/authentication, upload, deployment, reset, or commit; Linux remains unchanged.
- Keep existing pending/bootstrapPending credential refusal, MSI/version/service/config checks, marker validation, seed `no_log`/`diff: false`, and auth-independent credential preservation/cleanup safeguards.
- Remove Windows `win_uri`/administrator API login and all whole-home/state-root recursive reparse scans. Do not add client/helper frameworks, listeners, ACL policy, TCP/socket work, or unrelated path rejection.
- Target checks cover state root/staging/marker/MSI, `bin/splunkd.exe`, `etc/passwd`, system/local seed, and managed app `inputs.conf`/`outputs.conf`; validate ancestors outermost-in before reads/writes.
- Do not inspect `var/run/cli.socket` or reject unrelated state children. Keep configuration conflict meanings unchanged; traverse config candidates one directory at a time and prune unsafe reparse directories before reading files.
- `ready` means managed install/config/service/bootstrap metadata only, not valid login or event arrival. No password contents, auth attempts, or simulated native behavior.

## Review focus

1. Targeted managed-path and ancestor checks precede reads/writes; unrelated paths are not scanned.
2. Config-conflict categories remain intact while reparse directories are pruned before file reads.
3. No Windows API auth/client remains; readiness is bounded passwd metadata only.
4. Seed/passwd/pending recovery, `no_log`, `diff: false`, cleanup and ready-marker ordering remain intact.
5. Static tests make no runtime-success claim; future event-arrival verification needs separate authorization.

## File scope and install-write inventory

- Test first: `ansible/roles/ludus_splunk_collector/tests/test_windows_static.py`; leave `test_static.py` unchanged unless a specific discovery blocker requires a minimal adaptation.
- Production later: `tasks/windows/inspect.yml` and `configure.yml`; no socket helper/new file. `install.yml` stays unchanged, but inspect must guard its write targets: `C:\ProgramData\Ludus\SplunkCollector`, `staging`, `ownership.json`, and `staging\splunkforwarder.msi`.
- Documentation later: collector `README.md` and `docs/research/ludus-splunk-collector-windows.md`.

## Implementation checklist (after parent review of red evidence)

- [x] **Red tests:** Parent recorded 19 tests, 16 pass, and 3 expected failures in `/tmp/opencode/splunk-windows-simplification/red-tests.txt`; production was unchanged at red capture.
- [x] **Implement inspect preflight:** `inspect.yml` uses targeted path/type/reparse checks for managed paths and ancestors before marker/config reads; `cli.socket` and unrelated state entries are not globally rejected.
- [x] **Implement safe config traversal:** Conflict classification remains; configuration directories are enumerated incrementally and reparse entries are pruned before descent/read.
- [x] **Implement post-install guards and metadata readiness:** `configure.yml` starts with bounded managed-path guards, removes mandatory `win_uri`, waits up to 30 times with 10-second delay for regular nonempty `etc/passwd`, and retains seed/pending state on failure. Ready-marker write remains after cleanup.
- [x] **Update docs:** README/research distinguish managed metadata readiness from login/event arrival; live gaps and unresolved config-scanner limitation remain explicit.
- [ ] **Static verification:** Fast-generic runs `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/ludus_splunk_collector/tests -p 'test_*.py'` and `python3 .opencode/skills/ansible-validation/scripts/validate.py --role ansible/roles/ludus_splunk_collector`; retain raw logs and exit statuses.
- [ ] **Review/handoff:** Parent reviews scoped diff and test evidence. No live action or commit follows without separate authorization.
