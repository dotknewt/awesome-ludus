# Illustrative Windows Splunk logging range

This standalone example shows the intended Ludus dependency/order contract for
the Windows collector, Sysmon producer, and Debian Splunk receiver. It is not
deployment-ready: the template names and installed role identities are
placeholders/unverified and **must be checked against the target server** before
use. Do not infer an installed role's identity from a repository directory or
role metadata alone. The selected target server's Ludus version, template
catalog, installed-role catalog, and exact role identities remain unverified.

Before use, replace both `REPLACE_WITH_AVAILABLE_*_TEMPLATE` values with
templates confirmed present on the target server, and replace
`REPLACE_WITH_RESOLVABLE_SPLUNK_SERVER_ADDRESS` with an address resolvable from
the Windows VM. Confirm from the target server that the illustrative role IDs
`ludus_splunk_server`, `ludus_install_sysmon`, and `ludus_splunk_collector` are
installed and accepted, and that the collector's `depends_on` role references
match those installed IDs. The server VM is listed first, Sysmon is listed
before the collector, and the collector declares dependencies on both the
receiver role and Sysmon role. These declarations express the desired order;
they do not establish target-server compatibility.

`requirements.yml` records the current Ludus-installed collection baseline:
`ansible.windows` 2.7.0 and `community.windows` 2.3.0. This pin does not request
a collection update; reviewed role installation is a separate operation. The
prior static evidence used newer collections (`ansible.windows` 3.8.0 and
`community.windows` 3.3.0) and does not establish compatibility with this
baseline. Revalidate against the installed versions before claiming compatibility.

The example explicitly accepts the server role's license input and enables its
native receiver on TCP **9997**; both are opt-in role inputs. The receiver owns
the `winlogs`, `sysmon`, and `etw` indexes. The Windows collector routes
Security to `winlogs`, Sysmon to `sysmon`, and SilkService-Log to `etw`.
Security is the unfiltered baseline (`oldest`, `current_only=0`); no Security
exclusion is enabled. Sysmon installation/filtering remains owned by
`ludus_install_sysmon`; the collector does not invoke it implicitly. SilkService
is collection-only: this example does not install or configure its producer.

This does not include HEC, TLS, firewall rules, the full Splunk TA, optional
CIM assets, or PSTree configuration. It makes no claim about target-side role
availability, templates, runtime behavior, or deployment readiness. See
[`PRE-LIVE.md`](PRE-LIVE.md) for outstanding static and live gates.
