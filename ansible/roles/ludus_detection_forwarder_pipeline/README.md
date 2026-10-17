# Detection forwarder pipeline

This private orchestration role composes the existing Linux telemetry producer
and Universal Forwarder consumer. It validates the shared profile and reader,
then runs, in order:

1. `ludus_detection_forwarder` with `tasks_from: prepare`;
2. the default `ludus_detection_linux_logging` entrypoint;
3. `ludus_detection_forwarder` with `tasks_from: activate`.

All three roles must already be installed and discoverable by Ansible. The
wrapper consumes their existing variables unchanged. It requires
`detection_forwarder_profile` to be `gitlab`, `runner`, or `workload`, and
requires `detection_laurel_read_user: splunkfwd`. The distro `auditd` package,
tools, and loaded unit are prerequisites supplied outside this wrapper (on full
Ludus runs, packages precede user roles); this role does not install them.

Failures propagate immediately. There is no cross-role rescue or rollback:
preparation can remain complete when producer setup fails, and producer state
can remain complete when activation fails. Each included role retains its own
protected markers, credentials, and convergence behavior, so legal active
reruns are supported without a pipeline phase marker.

The source-only scope does not add accounts, packages, ACLs, sanitizers,
telemetry, Splunk-local inputs, or range wiring. Native Laurel remains
`/var/log/laurel/audit.log` with index `de_linux` and sourcetype
`linux:audit:laurel`; the existing rotation and profile input facts remain
authoritative and unchanged.

## Ordering evidence and limits

Official Ludus source reviewed at commit
`c6528cccb36f2e30c2fe896171ce1ffd62095a3c` shows that
`ludus-server/ansible/range-management/templates/user-defined-roles.yml.j2`
does not propagate `tasks_from`, while `ludus.yml` installs packages before
user roles on full runs. Installed-version behavior and selective-tag ordering
are not verified. Offline tests model composition; they do not establish real
package scripts, auditd/kernel behavior, Laurel compatibility or output
fidelity, log replacement/rotation, deployment, or guest readiness.
