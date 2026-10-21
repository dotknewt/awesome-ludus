# Windows time readiness — implementation proposal

Status: proposed, not approved for implementation. Template investigation takes priority.

## Goal and scope

Verify Windows time during initial provisioning before installing Sysmon or starting
the Splunk forwarder. No reboot hooks or scheduled tasks: the user verified that
correct time persists across reboots after synchronization.

## Proposed implementation

- Add a reusable `ansible/roles/ludus_windows_time/` role.
- Detect domain membership; use the AD hierarchy for members and configurable NTP
  for standalone clients. Do not alter the configured timezone.
- Ensure W32Time is enabled and running, request synchronization, and poll readiness.
- Attempt at most one service restart and resync as bounded recovery.
- Require synchronized status, valid source and stratum, recent synchronization,
  and measured clock offset within tolerance. Prefer locale-independent status
  collection over parsing English command labels.
- Fail with useful diagnostics if readiness cannot be established.
- Proposed defaults, not approved: standalone source `time.windows.com`, maximum
  offset one second, total readiness deadline three minutes.
- Recheck readiness on subsequent provisioning runs without restarting an already
  healthy service.

## Integration

In `docs/examples/splunk-dev1/range-config.yml`, order the Windows roles as time
readiness, Sysmon, then Splunk forwarder. Preserve the forwarder's Splunk-server
dependency. Leave telemetry role internals unchanged.

Repository inspection found no reusable Windows synchronization role. The dev1
example has no domain stanza and already sets `defaults.timezone: Europe/Oslo`.
Official configuration documentation states roles execute in listed order subject
to explicit dependencies: https://docs.ludus.cloud/docs/configuration/
Installed-server version compatibility and failure propagation remain unverified.

## Evidence and limitations

The user observed approximately six hours of initial clock skew. Resynchronization
corrected the clock but W32Time still reported leap indicator 3 and stratum 0.
Restarting W32Time and requesting rediscovery/resynchronization produced leap
indicator 0, stratum 5, an active peer, and approximately 13 ms measured offset.
This establishes recovery, not the cause of the initial skew.

The role would gate new telemetry installations, not prevent logging by agents
already installed in a VM/template. It cannot correct historical events or prevent
Windows boot events before provisioning. No log deletion is proposed.

## Verification plan

Use changed-file static checks following repository policy. With separate live
authorization, exercise fresh deployment, healthy rerun, and unavailable NTP;
confirm a readiness failure prevents subsequent telemetry installation. Static
checks do not establish runtime behavior or deployment readiness.

## Next step

Investigate `templates/no-windows-11-22h2-x64-enterprise/` for clock, timezone,
W32Time, virtualization, provisioning, and shutdown settings before deciding
whether this proposal should be implemented or revised.
