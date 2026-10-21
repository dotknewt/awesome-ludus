# Threat Hunting

Based on the [threat-hunting plan](../../docs/threat-hunting-range-blueprint_PLAN_v0.0.1.md), this range contains three servers using the plan's default Debian template. Ludus's default router is retained; no separate router VM is added.

| Server | vCPU | RAM | VLAN | IP last octet | Role |
| --- | ---: | ---: | ---: | ---: | --- |
| Splunk | 4 | 16 GB | 10 | 11 | `ludus_splunk_server` |
| Malcolm | 8 | 64 GB | 10 | 17 | `ludus_install_malcolm` |
| GitLab | 4 | 8 GB | 10 | 18 | `ludus_gitlab_ce` |

Sizing and VLAN/IP assignments follow the existing [constructing-defense range config](../constructing-defense/range-config.yml) for Splunk and Malcolm, and its [README](../constructing-defense/README.md) for GitLab. Total allocation is 16 vCPU and 88 GB RAM, excluding the default router. The plan also permits `no-ubuntu-24.04.2-x64-server-template` and `no-ubuntu-26.04.1-x64-server-template` alternatives.

The roles are in the source root: [`ludus_splunk_server`](../../ansible/roles/ludus_splunk_server), [`ludus_install_malcolm`](../../ansible/roles/ludus_install_malcolm), and [`ludus_gitlab_ce`](../../ansible/roles/ludus_gitlab_ce). The GitLab role's Debian 13 compatibility is assumed by the user and has not been independently established. Template availability and live installation behavior are unverified. Collection availability is managed by Ludus and is not treated here as a readiness blocker.

The Splunk role default for `ludus_splunk_server_accept_license` remains `false`. The user has accepted the applicable terms for this blueprint, so the Splunk VM explicitly opts in with `role_vars.ludus_splunk_server_accept_license: true`; this does not change the reusable role default or claim that deployment/runtime checks have been performed. See the official [range configuration documentation](https://docs.ludus.cloud/docs/configuration) and [range-config schema](https://docs.ludus.cloud/schemas/range-config.json).
