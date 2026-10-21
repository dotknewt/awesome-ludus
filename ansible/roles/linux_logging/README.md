# ludus_linux_logging

Install native `auditd` and Laurel v0.6.3 on Debian 13 (trixie) or Ubuntu
24.04/26.04, x86_64, using systemd. This role is independent: it does not
install, configure, or depend on a collector role.

> **Compatibility status:** runtime compatibility for the selected Laurel
> archive, auditd unit, and supported OS versions is not verified. Static checks
> do not establish deployment readiness. Live verification requires separate
> authorization.

## Requirements

- `ansible-core >= 2.16`, root/become access, HTTPS access to the pinned sources.
- If `/usr/sbin/auditctl` is present, the role reads current kernel status
  before package work. Existing auditctl status is checked before package
  installation whenever the command is present. If it is absent, the role installs only the `auditd`
  prerequisite with apt's `policy_rc_d: 101` to suppress package-triggered
  service startup, then confirms `auditctl` and checks immutable state before
  writing role policy or starting/reconfiguring auditd. This is the only
  bounded prerequisite mutation needed to inspect kernel audit state; users do
  not need to preinstall auditd.
- The requested Laurel log-reader accounts must already exist before the role
  starts. The default `debian` account is checked, not created. For a paired
  Universal Forwarder collector, run the collector role first and set
  `ludus_linux_logging_read_users: [splunkfwd]` (or include other explicitly
  existing readers). This role does not hide that ordering as a dependency.
- The role does not create or change template/login accounts. It only creates
  the dedicated `_laurel` system identity when absent.

## Inputs

All public inputs are in `defaults/main.yml` and use the
`ludus_linux_logging_` prefix.

| Input | Default | Purpose |
| --- | --- | --- |
| `ludus_linux_logging_read_users` | `[debian]` | Existing users granted per-file Laurel log ACLs. |
| `ludus_linux_logging_laurel_user` | `_laurel` | Dedicated system identity; only absent identity is created. |
| `ludus_linux_logging_laurel_log_dir` | `/var/log/laurel` | Laurel output directory. |
| `ludus_linux_logging_laurel_log_file` | `audit.log` | Laurel JSONL output filename within that directory. |
| `ludus_linux_logging_laurel_config_path` | `/etc/laurel/config.toml` | Role-owned transformed Laurel configuration path. |
| `ludus_linux_logging_audit_rules_path` | `/etc/audit/rules.d/60-ludus-linux-logging.rules` | Separate managed audit fragment. |
| `ludus_linux_logging_laurel_plugin_path` | `/etc/audit/plugins.d/laurel.conf` | Laurel audit plugin configuration. |

Artifact versions, URLs, SHA-256 values, and the protected cache directory are
also namespaced defaults. They are pinned and validated by the role; changing
those pins requires a reviewed artifact update, not an arbitrary URL override.

## Behavior and safety boundaries

- Installs the distribution `auditd` package and the checksum-pinned x86_64
  Laurel archive. The archive is extracted as data; no downloaded script is
  executed. The selected binary's reported version must contain `0.6.3`.
- Downloads the ConstructingDefense `audit.rules` and `config.toml` at commit
  `0cefe62755eebba7b226e611ece75160706e22f6` over HTTPS and checks their
  SHA-256 before use. The checksums were computed from safe HTTPS GETs on
  2026-10-20: `audit.rules` (27,422 bytes) is
  `fbcf55a50c76ffd8e8090c32a55d85015db0fda40d5ff1276e273d4a1af0f4a8`, and
  `config.toml` (5,625 bytes) is
  `8020587c28d90de86b1e52db3128d490b57e271221ef1ce249e73a23706bda34`.
  These are observed transport hashes, not publisher signatures. The inspected
  source has no verified redistribution license, so neither source file is
  vendored; attribution is retained here and in managed outputs.
- A narrow pure filter parses `-w`, `-F path=`, and `-F dir=` targets (including
  optional `/usr/local/bin/kubectl`), removes active global `-D`, `-e`, and `-i`
  controls, and comments out only rules with an absent exact target, an
  unresolvable named uid/gid operand, or SELinux predicates when the SELinux
  interface is absent. Each omitted rule retains its original text and a
  specific reason in the managed fragment. Numeric identities and `unset`
  retain native meaning. Unexpected lookup failures and malformed policy fail
  rather than silently broadening or dropping rules. Exact repeated active
  lines are deduplicated in first-occurrence order with a comment; arbitrary
  semantic duplicates are not inferred.
- Existing unmarked `/etc/audit/audit.rules` containing active rules, unrelated
  fragments, and runtime rules are never deleted or globally cleared. An empty
  or comment-only placeholder and a file explicitly marked as augenrules-
  generated are not treated as unmanaged policy; an unmarked output containing
  active rules is refused. On managed
  fragment changes it invokes `augenrules` without `--load` to generate the
  persistent merged `/etc/audit/audit.rules` output for boot. For an already
  active service, the managed fragment alone is loaded with `auditctl -R` so
  this operation appends its rules without a global reset. The role then sends
  auditd's supported `auditctl --signal reload` signal for configuration/plugin
  changes; signal delivery alone is not proof Laurel started, so a bounded
  process-readiness check is also required.
  Existing immutable kernel state (`enabled=2`) is rejected before role policy
  or service mutation (and before package work whenever auditctl already exists).
  Because audit rules are ordered and `auditctl -R` appends, pre-existing rules
  can affect filter precedence; inspect the current runtime policy and arrange
  any required policy ordering through an authorized operator procedure. If a
  managed fragment is edited after it has already been loaded, this role does
  not attempt a global reset or remove runtime-only rules; reconcile the old
  role rules deliberately before applying changed policy. The role detects a
  changed managed fragment while auditd is active and fails before overwriting
  or loading it; it will not silently accumulate stale role rules.
- `augenrules --check` is a content-comparison operation, not a non-mutating
  syntax validator. The role does not present it or an imaginary `auditctl`
  check flag as syntax validation. Loading occurs through the actual
  `auditctl -R` handler; malformed rules may be rejected by auditctl and need
  explicit operator recovery. Before a fresh start, the role refuses merged
  policy containing active `-i` so an ignored load error cannot be hidden. It
  On a fresh start only, it inspects effective unit/drop-in text with
  `systemctl cat` and accepts either the Debian 13 `Requires`/`After` dependency
  on the `audit-rules.service` oneshot loader or the supported legacy auditd
  `ExecStartPost` hook. Unsupported or overridden shapes fail closed. After a
  fresh start it checks the selected loader's recorded execution result; the
  oneshot must report `Result=success`, `ExecMainCode=1` (normal exit), and
  `ExecMainStatus=0`. It does not require a oneshot to remain active. An already
  active auditd skips startup-layout/result gates. These are static contracts;
  selected-version behavior still requires authorized native verification.
- Role-owned configuration files are marked and protected against symlinks or
  unmarked pre-existing files. Unrelated audit plugin/configuration files are
  not replaced. `_laurel` is created only if absent; an existing incompatible
  account is rejected rather than rewritten. The role does not create or change
  template/login accounts.
- Laurel v0.6.3 opens log files mode `0600`, applies named-user ACL entries to
  each new file, and reapplies them on file open after rotation; a default ACL
  on the directory alone is insufficient. Its configured parent directory is
  owned by Laurel and mode `0755` according to the inspected pinned source.
  When Laurel starts as root and drops to `_laurel`, the inspected Linux build
  retains `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` for its file-reading and
  process-enrichment behavior. The collector ACL grants read access only; it
  does not remove Laurel's capability requirements. This service/capability
  behavior still needs authorized native verification.
  In particular, Laurel retains `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE`
  under the inspected root-to-`_laurel` UID/GID drop path; no capability opt-out
  is exposed by the inspected v0.6.3 configuration.
- The preserved config defaults include rotation size `5000000`, ten
  generations, array-form execve arguments, PID/container/script/user-group
  enrichment, `LD_PRELOAD`/`LD_LIBRARY_PATH`, and `filter-action = "drop"`.
  The default reader is `"debian"`; the generated config uses
  `directory = "/var/log/laurel"`, `user = "_laurel"`, and an explicit
  `file = "audit.log"` path unless those role inputs are safely overridden.
- The role refuses active auditd when kernel status reports `enabled=0` and
  checks the final kernel enabled state after a permitted fresh start. It never
  forces `auditctl -e 1`. If auditd was inactive but the kernel already has
  runtime rules, it fails rather than allowing startup's merged-policy load to
  reset that state. Debian/Ubuntu auditd units may refuse ordinary manual
  restarts; this role does not restart auditd for configuration changes.
- A root-only `/var/lib/ludus-linux-logging` state directory contains a pending
  marker before managed config/rules/plugin writes and an applied SHA-256 digest
  record only after rules/service/plugin readiness and on-disk digest checks
  pass. A pending marker causes the next run to fail closed with concrete
  inspection/recovery guidance; it is never automatically cleared or replayed.
  Existing role-marked files without a digest marker also require deliberate
  recovery. When the daemon is already active and all recorded digests and
  managed-file contents match the desired state, the role skips pending-marker
  creation, digest rewriting, and marker removal on convergence. Laurel
  config/plugin digest mismatches explicitly request auditd reconfiguration
  even when the desired file bytes are already present; a clean applied marker
  does not trigger it. Rule-fragment metadata repair preserves ordinary copy
  change reporting but does not load policy unless its content changed. The
  digests identify exact managed file contents, not proof of end-to-end audit
  event ingestion.

## Example

```yaml
- hosts: linux_hosts
  become: true
  roles:
    - role: ludus_linux_logging
  vars:
    # Override only when the requested reader exists before this role runs.
    ludus_linux_logging_read_users: [splunkfwd]
```

## License and attribution

Role-authored content is GPL-3.0-or-later. Laurel is GPL-3.0-or-later. The
ConstructingDefense audit policy/config are fetched at a pinned revision but
not redistributed; their inspected repository contents did not establish a
redistribution license. Upstream attribution: Antonlovesdnb/ConstructingDefense,
commit `0cefe62755eebba7b226e611ece75160706e22f6`.
