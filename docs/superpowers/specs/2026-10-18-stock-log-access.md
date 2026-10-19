# Scoped native access to canonical Linux logs

## Intent and approved boundary

The user approved giving the existing package reader group read-only access to
`/var/log/auth.log` and `/var/log/syslog`, retaining root ownership and mode
`0640`, and configuring their native producer to recreate them with that policy.
The user explicitly accepts loss of ordinary `adm` readership of these files
and new generations carrying the selected group. Root administrative access
remains; existing rotated archives are not migrated.

Use `splunkfwd` for UF hosts and `splunk` when the Linux role serves the local
collector. Do not create accounts/groups, change memberships, grant ACLs or
capabilities, change telemetry/paths, or change rotation schedules/retention.
Implementation and offline validation are authorized, not deployment, guest
testing, remote service changes, gate promotion, commits or cleanup.

## Increment and boundaries

Implement in the private Linux logging role and verify its existing UF pipeline.
Test Linux role support for both reader names. Actual Splunk-local orchestration
remains Task8 work: after package/account provisioning and before bootstrap;
do not modify the independent Splunk role or claim that ordering is integrated.
Preserve the accepted, uncommitted Laurel archive installer and artifact tests.

## Supported native configuration

Approved composition amendment: Forwarder bootstrap must retain mode `0700` on
the root-owned shared marker directory `/var/lib/detection-engineering`, matching
the private stock-access requirement. Change no seed-directory permissions or
other Forwarder behavior. Restore strict pipeline convergence and cover the
bootstrap directory policy in a focused regression. This authorizes only
uncommitted implementation/offline tests, not live changes.

The initial profile uses the exact reviewed Bookworm reference bytes recorded
in `.superpowers/sdd/2026-10-18-stock-log-access/reference-inputs/` and its
`fetch-status.tsv`. This is not a deployment-template selection or general
Debian/Trixie compatibility claim. Unknown effective configurations refuse.

- Required: stock rsyslog configuration, global logrotate configuration,
  rsyslog rotation stanza and its HUP helper.
- Optional included rotation fragments: exact reviewed `apt`, `dpkg`,
  `alternatives`, `btmp`, `wtmp` contents. Their local policies do not alter the
  canonical logs. Unknown files, contents or include arrangements refuse.
- The supported rsyslog include glob has no matching configuration files;
  arbitrary additional producer actions/defaults are not accepted.
- Do not rewrite rotation configuration. Bare global `create` must remain
  effective for the unchanged rsyslog stanza and inherit original attributes.
- Preserve each original selector line byte-for-byte. Immediately precede each
  canonical action with `$FileGroup <reader>` and immediately restore
  `$FileGroup adm` afterward. Source in both reviewed `tools/omfile.c` tags
  captures the group per action; unrelated actions retain their original group.
  No RainerScript conversion, output duplication, template/sync/buffer change.
- Accept the original reference configuration or its deterministic generated
  form for this reader, not a configuration adopted for a different reader.
- Validate the complete supported candidate with `rsyslogd -N1 -f <candidate>`
  before publication. Recheck reference/include snapshots before mutation.

## Preconditions and application

The existing auditd/account/source-existence checks remain. Insert private
stock-access orchestration before common-source UID read checks and Laurel
mutation. Canonical path variables cannot redirect this operation.

Require installed rsyslog/logrotate, available validator, a loaded active
producer using its expected configuration, and a nonroot selected reader with
the verified existing nonzero package-group identity. Reject root/adm aliases;
do not claim perpetual or exhaustive NSS membership control. The grant is to
the approved existing group and therefore its actual members.

The native producer observation combines successful `systemctl show` properties
for `rsyslog.service` with `/proc` observations of its MainPID. Require loaded,
active/running, positive MainPID, no DropInPaths/RootDirectory/RootImage override,
and exactly one configured ExecStart with executable `/usr/sbin/rsyslogd` and
argv `[/usr/sbin/rsyslogd, -n, -iNONE]`. A narrow decoder accepts the supported
systemd property record; unrecognized/multiple command records refuse rather
than guess. Check the running process executable matches the validator binary,
its NUL-delimited argv matches that vector, and its root/mount context matches
the helper's host context. This profile accepts no alternate `-f` configuration,
wrapper, chroot or namespace. Recheck MainPID/process start identity across the
observation to detect replacement; observation failure is unknown, not inactive.
Together these bind the default `/etc/rsyslog.conf` path and restart command to
the checked producer. Repeat observation before mutation and after application;
an on-disk service reference alone does not establish runtime identity.

Require existing root-owned regular, single-link, distinct canonical files,
mode0640, group either adm or the selected reader, with trusted parents and no
extended access ACLs. Reject symlinks, untrusted objects and missing sources;
do not fabricate empty files or telemetry. Task8 must supply an active producer
and naturally materialized files. Preserve contents and unrelated resources.

Use no-follow descriptor-based validation/group updates, private writer
serialization, and source/config identity rechecks. Provisioning must exclude
concurrent rotation/configuration administration; detection is not atomic
isolation against arbitrary root actors. No unverified rotation-lock protocol.

After all preflight and candidate checks: invalidate prior private applied
state, migrate auth group then syslog group, atomically publish candidate if
different, and apply producer configuration when required. HUP only reopens
files; use the validated restart path for configuration application. Do not
stop/restart the consumer or mutate its credentials/lifecycle.

A protected private applied digest binds desired configuration, accepted
profile and reader UID/GID. Write it only after active-producer, metadata and
actual-reader read checks succeed. It is not a new factual gate or public
phase. Fully converged runs do not rewrite/restart. A metadata-only repair with
an already valid applied configuration needs no restart.

## Failure contract

Preflight/candidate failures leave operational metadata/configuration unchanged;
private staging is not operational mutation. After mutation, report changed
objects, failure stage and observed producer state; do not claim rollback.
Mixed adm/reader group states are retryable after full preflight. Published
configuration without an applied digest requires reapplication. A failed restart
may leave rsyslog inactive: stop downstream, preserve the consumer, and refuse
ordinary retry until separately authorized operational recovery. Never publish
success/readiness after failed verification or marker write.

`producer_active` in helper results is tri-state: true only for a successfully
observed active producer, false for successfully observed inactive/failed state,
null for query/read failure, transition, inconsistent identity or unsupported
observation. All states other than fully identity-validated active block ordinary
preflight without mutation. After failed restart, attempt observation and report
its actual tri-state, but fail regardless of an active result. A later ordinary
retry can proceed only after a fresh fully valid active observation and all
other preflight checks; it never starts an inactive or indeterminate producer.
Missing applied digest forces reapplication only after those checks. Unknown
state is not converted into a recovery authorization or a permanent latch.

## Evidence boundary

Private finalization is part of truthful result reporting. Finalize owned
resources before assembling JSON; attempt each descriptor close once and retain
primary operational diagnostics alongside ordered `cleanup_errors` (operation,
logical path/resource, errno, message). Operational success plus cleanup failure
returns stage `cleanup` and nonzero exit, retaining the valid applied marker and
last producer observation. Operational failure retains its stage/error. Account
for a candidate whose removal is unconfirmed; never invent certainty or roll
back successfully applied configuration for a private cleanup failure. Compute
`changed` after cleanup accounting. No broad leftover removal is authorized.

Tests exercise actual helper policy and actual Linux/pipeline main entrypoints.
Real filesystem operations can be exercised in private temporary trees; local
UID1000 and missing rsyslogd require explicit models for root identity/group
changes, native syntax validation, producer services and rotation. Test-only
adapters must not bypass production policy or introduce a production test mode.
DAC derives from modeled UID/GID/mode/inode state. Recreation derives from
applied rendered actions; rotation derives from unchanged accepted configuration
and prior metadata. HUP is reopen-only; restart loads configuration/groups.

Required failures include invalid profiles/identities/objects and interruption
around each metadata/configuration/application/digest boundary. Assert source,
producer, consumer, marker, unrelated-log/archive and configuration final states.
Selected-version syntax, live DAC/rotation, MAC/capabilities, ingestion and
deployment readiness remain separately authorized verification work.
