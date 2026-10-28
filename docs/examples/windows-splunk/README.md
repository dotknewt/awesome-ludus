# Illustrative Windows Splunk logging range

This standalone example shows the intended Ludus dependency/order contract for
the Windows collector, Sysmon producer, and Debian Splunk receiver. It is not
deployment-ready: the template names and installed role identities are
placeholders/unverified and **must be checked against the target server** before
use. Do not infer an installed role's identity from a repository directory or
role metadata alone. The selected target server's Ludus version, template
catalog, installed-role catalog, and exact role identities remain unverified.
For the server specifically, the canonical source-local identity is
`linux_splunk_server`, used by this example for both the server assignment and
dependent `depends_on.role` reference. Older source/catalog aliases such as
`ludus_splunk_server` and `ludus_splunk` are historical and are not current
source-local references. Installed server identity remains unverified; confirm
the target server identity before migrating a deployed range. See the staged
[role identity migration guide](../../role-identity-migration.md).

Before use, replace both `REPLACE_WITH_AVAILABLE_*_TEMPLATE` values with
templates confirmed present on the target server, and replace
`REPLACE_WITH_RESOLVABLE_SPLUNK_SERVER_ADDRESS` with an address resolvable from
the Windows VM. Confirm from the target server that the illustrative role IDs
`linux_splunk_server`, `ludus_install_sysmon`, and `dotknewt.splunk_forwarder` are
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
the `winlogs` and `sysmon` indexes. The consolidated Windows forwarder uses the
merged role's input-driven `splunk_forwarder_inputs` behavior; this example
explicitly routes Security to `winlogs` and Sysmon to `sysmon`. No Security
exclusion is enabled. Sysmon installation/filtering remains owned by
`ludus_install_sysmon`; the forwarder does not invoke it implicitly. Optional
SILK autoconfiguration is omitted because the standalone role has no equivalent;
see the blocked `SPLUNK-003` backlog item.

This does not include HEC, TLS, firewall rules, the full Splunk TA, optional
CIM assets, or PSTree configuration. It makes no claim about target-side role
availability, templates, runtime behavior, or deployment readiness. See
[`PRE-LIVE.md`](PRE-LIVE.md) for outstanding static and live gates.
