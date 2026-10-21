# Threat Hunting

Based on the [threat-hunting plan](../../docs/threat-hunting-range-blueprint_PLAN_v0.0.1.md), this range contains three servers using the plan's default Debian template. Ludus's default router is retained; no separate router VM is added.

| Server | vCPU | RAM | VLAN | IP last octet | Role |
| --- | ---: | ---: | ---: | ---: | --- |
| Splunk | 4 | 16 GB | 10 | 11 | `ludus_splunk_server` |
| Malcolm | 8 | 64 GB | 10 | 17 | `ludus_install_malcolm` |
| GitLab | 4 | 8 GB | 10 | 18 | `ludus_gitlab_ce` |

Sizing and VLAN/IP assignments follow the existing [constructing-defense range config](../constructing-defense/range-config.yml) for Splunk and Malcolm, and its [README](../constructing-defense/README.md) for GitLab. Total allocation is 16 vCPU and 88 GB RAM, excluding the default router. The plan also permits `no-ubuntu-24.04.2-x64-server-template` and `no-ubuntu-26.04.1-x64-server-template` alternatives.

The roles are in the source root: [`ludus_splunk_server`](../../ansible/roles/ludus_splunk_server), [`ludus_install_malcolm`](../../ansible/roles/ludus_install_malcolm), and [`ludus_gitlab_ce`](../../ansible/roles/ludus_gitlab_ce). The GitLab role's Debian 13 compatibility is assumed by the user and has not been independently established. Template availability and live installation behavior are unverified. Collection availability is managed by Ludus and is not treated here as a readiness blocker.

The shared `splunk_accept_license` default remains `false`. This example explicitly opts in through top-level `global_role_vars` after accepting applicable terms; this does not change the reusable role default or claim deployment/runtime checks have been performed. The server role has no supported configurable index-list input: its existing tasks create hard-coded `wineventlog` and `sysmon` indexes, and forwarder input index names do not configure server indexes. See the official [range configuration documentation](https://docs.ludus.cloud/docs/configuration) and [range-config schema](https://docs.ludus.cloud/schemas/range-config.json).

The server role's installed identity has not been verified. The example's role
IDs must be checked against the target Ludus server; do not infer installed
identity from the source directory or metadata. If changed, update matching
`roles` and `depends_on.role` references consistently.
