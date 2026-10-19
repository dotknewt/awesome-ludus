# Implementation plan: Linux logging and Splunk collection

> **For agentic workers:** Use subagent-driven-development for the independent
> writer tasks below. Track completion using the checkboxes.

**Goal:** Add independent Linux logging and Universal Forwarder roles and an
optional receiver to the existing server role.

**Architecture:** Three disjoint role writers share the interfaces below.
Collector account creation precedes Laurel startup; the separate server is an
explicit deployment dependency, not an implicitly included role.

**Tech Stack:** Ansible builtin modules, YAML/Jinja, auditd, Laurel 0.6.3,
Splunk Universal Forwarder 10.6.1.1, Python static contract tests.

**Spec:** `docs/superpowers/specs/2026-10-20-ludus-linux-splunk-logging-design.md`

**Status:** awaiting implementation-plan confirmation. No deployment, live
testing, guest probes, tool installation, or commits are authorized.

## Shared contract

- New roles support Debian 13, Ubuntu 24.04, and Ubuntu 26.04, amd64, and
  systemd. `ludus_splunk_server` remains Debian 13 only.
- No hidden role includes; metadata dependencies are none; use builtin
  Ansible modules where possible. Preserve the approved server-before-client
   `depends_on` ordering: separate server VM first; collector → logging on
   each client VM.
- Server defaults: `ludus_splunk_server_receiver_enabled: false` and
  `ludus_splunk_server_receiver_port: 9997`. Own a dedicated receiver app,
  preserve unmanaged config, restart and check the configured listener after
  start/restart.
- Collector defaults: required string `ludus_splunk_collector_receiver_host`
  is empty; `ludus_splunk_collector_receiver_port: 9997`; monitor mapping
  `{path: /var/log/laurel/audit.log, sourcetype: laurel:json, index: main}`.
  Use fixed non-root `splunkfwd` and vendor-managed `SplunkForwarder.service`.
- Logging defaults: `ludus_linux_logging_read_users: [debian]` and
  `/var/log/laurel`; paired composition overrides readers to `[splunkfwd]`.
  Missing requested reader accounts fail before mutation.
- No firewall mutation, package upgrades, broad forwarder capabilities, TLS,
  recursive `/var/log`, custom index creation, or unmanaged app overwrites.
  Port 8089 remains vendor/localhost fresh-auth behavior; do not open it.

## Writer 1 — existing server receiver

**Files:** `ansible/roles/ludus_splunk_server/defaults/main.yml`,
`tasks/main.yml`, `README.md`, and focused static tests/syntax harness.

1. Add the two namespaced receiver inputs and validate boolean/port/conflict
   state before mutation.
2. Write only a role-owned receiver app containing the configured
   `[splunktcp://<port>]` listener; disable removes only that managed app.
3. Restart the proper service only after managed changes, then wait for and
   check the configured listener. Never overwrite unrelated Splunk config.
4. Document no firewall/8089 changes and the disabled default.

## Writer 2 — new collector

**Files:** new `ansible/roles/ludus_splunk_collector/` role: `meta/main.yml`,
`defaults/main.yml`, `tasks/main.yml`, templates/files, `README.md`, license,
and truthful focused `tests/` plus `syntax.yml`.

1. Add platform and input assertions before mutation; require a nonempty
   receiver host, validate port, paths, mappings, URL, checksum, and license.
2. Download and verify the exact UF 10.6.1.1 amd64 `.deb`; inspect package
   identity/version and refuse mismatches or upgrades.
3. Create/discover fixed non-root `splunkfwd`, use the vendor boot-start
   procedure and distinct `SplunkForwarder.service`, and inspect effective
   identity/ownership. Do not add broad capabilities.
4. Implement fresh-only seed creation/removal after authenticated init;
   preserve initialized auth and refuse unmanaged seeds.
5. Own dedicated apps for `inputs.conf`/`outputs.conf`, monitor the default
   mapping, permit an absent producer file, avoid recursion/raw duplication,
   restart on changes, and verify service readiness.
6. Keep collector independent: it may apply narrowly scoped read access only
   where contracted, never modify logging config, and never include logging.

## Writer 3 — new Linux logging

**Files:** new `ansible/roles/ludus_linux_logging/` role: metadata,
defaults, tasks, templates/files, `README.md`, license, focused tests, and
`syntax.yml`.

1. Assert supported Debian/Ubuntu versions, amd64/systemd, reader accounts,
   and all inputs before mutation. Download upstream `audit.rules` and
   `config.toml` at the immutable research commit with HTTPS URLs and
   checksums; do not vendor files or execute remote scripts.
2. Download the pinned Laurel v0.6.3 archive using the observed research hash
   and clearly document that it is transport provenance, not publisher
   authentication. Preserve attribution/license.
3. Render a role-owned audit fragment, preserving unrelated rules. Remove
   only global deletion and immutable directives; parse exact path-watch
   syntax and omit watches whose paths are absent. Record/document review of
   all other path predicates rather than silently weakening policy.
4. Preflight grammar and use `augenrules --check`; do not invent a
   non-mutating `auditctl` syntax flag. Handle immutable state explicitly;
   handlers reload/HUP only after changes. Use documented auditd service
   control differences, including Ubuntu refusal of manual stop/start.
5. Configure Laurel explicit `read-users`; default `[debian]`, paired
   `[splunkfwd]`. Reader absence fails before mutation. Keep default directory,
   enrichment, rotation, and producer semantics explicit; do not pretend a
   default directory ACL solves Laurel's per-file ACL reset.

## Static verification budget

One fast-generic validator owns command verification after all writers finish,
with no edits or live actions. Inventory only these three roles and their metadata
dependencies. Run `validate.py` (required), each role's truthful `syntax.yml`
and Python unit tests, YAML/Jinja/static contract checks, and `git diff --check`.
If an executable is unavailable, report `NOT AVAILABLE`; missing required
collections when Ansible is available are failures, not tool unavailability.
Do not install tools or collections. Tests must not use mocks,
simulations, or stateful fakes. Reuse the research evidence already cited;
perform no broad additional research.

## Review focus and handoff

Parent self-reviews this plan before handoff. Review specifically for: (1)
platform assertions and server scope, (2) writer ownership/unmanaged config,
(3) audit transformation and immutable-state safety, (4) Laurel/UF identity,
seed, and reader lifecycle, and (5) exact ordering, endpoint, and readiness
contracts. No commits unless the parent explicitly requests them.

## Execution checklist and focused checks

- [ ] Server writer first adds static tests for disabled-by-default receiver,
  port validation before mutation, unmanaged-app preservation, changed-only
  restart, and configured listener readiness in `tests/test_static.py`.
- [ ] Collector writer first adds `tests/test_static.py` for exact artifact
  pin, Debian/Ubuntu platform allowlist, required host, monitor stanza safety,
  fixed non-root service identity, fresh-only secret handling, and missing-log
  tolerance. Add a guarded `tests/syntax.yml` exercising the actual entrypoint.
- [ ] Logging writer first adds `tests/test_static.py` for pinned sources,
  platform allowlist, reader preflight, removal of global audit controls,
  missing-path handling, immutable-state refusal, and no remote shell script.
  Add a guarded `tests/syntax.yml` with explicit role-specific inputs.
- [ ] Validator records initial failing static tests before implementations.
- [ ] Each writer implements its numbered steps, templates, defaults,
  metadata, handlers as needed, README, and narrow static tests.
- [ ] Parent reads all artifacts and reconciles interfaces and review focus.
- [ ] Validator runs `python3 -m unittest discover -s <role>/tests -v` for
  each of the three roles: all selected tests must pass.
- [ ] Validator inventories dependencies/harnesses and runs
  `python3 .opencode/skills/ansible-validation/scripts/validate.py`
  with an explicit `--role` for each selected role and coverage-gap arguments
  for anything unresolved. PASS or warning-only means static-only evidence;
  actual failures and coverage errors must be resolved.
- [ ] Validator runs `git diff --check`, reports scoped changes and preserves
  the pre-existing `blueprints/threat-hunting/range-config.yml` modification.
- [ ] Parent records evidence and limits; live fresh install, rerun, reboot,
  rotation, ingestion, and failure scenarios remain NOT RUN.
