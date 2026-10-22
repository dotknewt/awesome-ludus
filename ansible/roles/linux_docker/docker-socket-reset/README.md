# Docker socket access after a connection reset

## Incident and scope

On 2026-10-19, the `thrunt-malcolm` Docker Compose pull reported access denied
to `docker.sock` after a group change and Ansible `meta: reset_connection`.
Later diagnostics showed the expected groups, socket mode `660`, and a daemon
that had been ready earlier. The incident's causal trace remains unverified,
even though the controller hotfix described below has since been applied.

The installed Ludus `group_vars/debian.yml` templates `ansible_user` and
`ansible_ssh_extra_args`. User-authorized privileged preflight confirmed the
running Ludus environment selects `/usr/local/bin/ansible-playbook`, Ansible
core 2.16.14, configured by `/etc/ansible/ansible.cfg`, with modules under
`/usr/local/lib/python3.13/dist-packages/ansible` and Python 3.13.5. A separate
`/opt/ludus/runtimes/ansible-windows-ssh` runtime exists and must remain
untouched. Ansible 2.16/Python 3.13 is an unsupported baseline; this patch
does not resolve that compatibility risk.

## Controller hotfix (applied)

`ansible-core-2.16.14-reset-connection.patch` contains only the three upstream
production-file changes, adapted to the v2.16.14 source context. The fix
moves connection-variable templating into
`ConnectionBase._resolve_option_variables` and uses that helper during both
normal connection setup and `reset_connection`. It addresses the case where
reset receives raw, untemplated connection variables. The patch was applied to
the shared system Ansible installation with the user's explicit authorization;
the patch file itself is not an automatic apply script.

Upstream attribution and references:

- [Upstream patch](https://github.com/ansible/ansible/pull/84440.patch)
- [Original PR #84240](https://github.com/ansible/ansible/pull/84240)
- Commit `da27a110776158db3e110086e5070b3d8492f648`; cherry-picked from
  `59d9737788d63ea4e17b74d3c3ca1a0cf03f89ba`
- [Ansible v2.16.14 task executor source](https://github.com/ansible/ansible/blob/v2.16.14/lib/ansible/executor/task_executor.py)
- [Ansible v2.16.14 connection base source](https://github.com/ansible/ansible/blob/v2.16.14/lib/ansible/plugins/connection/__init__.py)
- [Ansible v2.16.14 strategy source](https://github.com/ansible/ansible/blob/v2.16.14/lib/ansible/plugins/strategy/__init__.py)

Original installed-file SHA-256 values (before the hotfix):

| File | SHA-256 |
| --- | --- |
| `executor/task_executor.py` | `94b42afbd4e45f66c249056f7d2d02826d5a822571de116caa67685d0f896393` |
| `plugins/connection/__init__.py` | `f3b440f1b21a692d0b1990994297492448008c37760cf2605de6c232362b4f11` |
| `plugins/strategy/__init__.py` | `5738e5a52d9492e39809fb6c8d181216ef32a38d918eba12e635fd36b21f87f8` |

## Application safeguards and impact

The application was explicitly approved. For any future reapplication or
rollback, first confirm the service's actual Ansible executable and runtime,
exact Ansible version, and all three file hashes. Require no active
Ansible/package jobs and an approved maintenance window.
The intended target root is
`/usr/local/lib/python3.13/dist-packages`; with that root, `-p1` strips the
`a/` or `b/` prefix and targets `ansible/...` paths beneath it. Review and
dry-run against the exact target files before any future application; no apply
commands are provided here.
Back up all three files with ownership and modes preserved. Reject unknown,
modified, or partially patched files; do not force or guess around conflicts.
If any write fails, keep Ansible jobs paused and inspect all three current
hashes before recovery. Only restore a file whose current hash matches its
known original or expected patched hash; leave already-original files alone.
If any file has an unknown hash, stop and preserve it and the backups for
manual recovery rather than overwriting it. Verify all three original hashes
before resuming jobs. The same safeguards apply to later rollback: do not
overwrite subsequent edits. After a successful change, verify the three
resulting files and their ownership/modes and confirm that only the intended
source hunks changed.

This affects every consumer of the shared system Ansible installation.
Package upgrades may overwrite a manual patch. Do not globally set
`LUDUS_ANSIBLE_BINARY`: that can bypass Ludus's Windows runtime selection.
Do not substitute a blanket Ansible upgrade (which risks Python 2 guest
support changes), Ludus role changes, socket permission broadening, or a root
bypass.

## Application evidence and remaining verification

Static artifact validation was completed 2026-10-20: original file hashes
matched the recorded installed files and official v2.16.14; changed lines
matched upstream PR #84440. The patch dry-run/apply on local scratch copies
used `--fuzz=0 -p1` with no offsets, Python `ast.parse`/`compile` passed for all
three files, and reverse application restored the original hashes.

The user ran the guarded application wizard with explicit approval on
2026-10-20. Its operator log is
`/home/dotme/docker-reset-hotfix.MIooLQ/application.log`; it records successful
pre- and post-application service runtime/version/config/module-path/import
checks, syntax/hash checks, and retained backups at
`/var/backups/ludus-ansible-reset-rrf8afhd` (staging subdirectory `stage`).
Parent-session read-only SSH checks independently confirmed all three files
are `root:root`, mode `0644`, and match the expected patched hashes below.
No service restart, deployment, guest probe, or role entrypoint execution
occurred.

Installed patched-file SHA-256 values independently confirmed after application
(also expected from local scratch validation):

| File | SHA-256 |
| --- | --- |
| `executor/task_executor.py` | `dfb1c8f5f47b15f6cde03d85a4eaf962d69024d83f1c408eaeacee789cc50367` |
| `plugins/connection/__init__.py` | `e8ac3275d8d27b6ad74716893b55d05af781dd6b19d7fa04f475bedec8c093f2` |
| `plugins/strategy/__init__.py` | `39a4aa5106fc30ed37abf9450e8885975a77ba9d7acb56147d4963a07f973bb3` |

Patch SHA-256: `89ec1c024e64ea9e2f355dd3be9d5c4ce864e6545fa159390198db08a52cfe78`.
The service runtime is Ansible core 2.16.14 on system Python 3.13.5, an
unsupported baseline not corrected by this patch. Service-context import and
`--version` checks passed according to the operator log; a full Ansible play,
Docker role behavior, fresh-deployment success, and convergence have NOT been
verified. The incident's original causal trace remains unconfirmed. Fresh
deployment/role verification is a separate, not-yet-authorized step.

If separately authorized, live verification must exercise the actual Docker
role entrypoint on a fresh VM with a stale pre-membership connection, then perform
the exact same-context read-only `id` and Docker socket access check. Capture
the verbose socket-reset trace and verify convergence. Re-running against the
currently fixed VM is not an adequate substitute. Record the actual runtime,
static checks, live evidence, and anything left unverified independently.
