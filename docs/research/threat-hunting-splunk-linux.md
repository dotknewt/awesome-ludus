# Threat-hunting Splunk on Linux: quickest first start

**Research date:** 2026-10-19  
**Scope:** Static review of local Constructing Defense artifacts and cited Splunk Docker documentation. No deployment or host inspection.

## Resource precedent (not a Linux minimum)

| VM | Evidence in repository | Relevance |
|---|---|---|
| Splunk | `blueprints/constructing-defense/range-config.yml:17-23`: DC at VLAN 10, `.11`, 4 vCPU / 16 GiB. It is explicitly a Windows DC running Splunk, so this is precedent, not a Linux sizing recommendation. | Candidate address and resource reference only. |
| Malcolm | `blueprints/constructing-defense/range-config.yml:178-187`: VLAN 10, `.17`, 8 vCPU / 64 GiB. | Separate packet-monitoring service; not part of the proposed Splunk sizing. |
| GitLab | `blueprints/constructing-defense/README.md:10-20,40`: VLAN 10 `.18`, 4 CPU / 8 GiB; README says Debian 12. These details are README-only, not present in current `range-config.yml`, and Debian 12 conflicts with the new allowed-template list. | Historical topology note; do not treat as current deployment config. |

The tentative sum for these three VMs is **16 vCPU / 88 GiB**, excluding the router. No disk sizing evidence was found. Do not copy old secrets, domain settings, packages, or roles into a new Linux server configuration. This research leaves the existing range configuration unchanged.

## Existing Splunk roles are not turnkey Linux server installers

- `ansible/roles/role_splunk_install/tasks/main.yml:1-18` invokes Windows PowerShell and downloads/installs a Windows MSI. It also configures indexes/apps/listening and disables the firewall (`:20-68`); it is not a Linux installer. The Universal Forwarder is a collector, not the Splunk Enterprise server.
- `ansible/roles/ludus_detection_splunk/tasks/main.yml:2-68` requires a fully identified Debian artifact (including version, build, URL, SHA-256 and download-auth status), explicit trial/license and HEC/search capability declarations, admin credentials, and Linux host/Laurel logging inputs. Later it includes `ludus_detection_linux_logging` (`:368-372`). This is a broader, evidence-gated detection deployment, not a minimal turnkey first-start installer. Do not recommend drop-in reuse without satisfying its complete scope.

## Fastest verified first start: official Enterprise container

Splunk's official [`splunk/splunk` Docker quickstart](https://github.com/splunk/docker-splunk#quickstart) (README fetched from [the upstream repository](https://raw.githubusercontent.com/splunk/docker-splunk/develop/README.md)) documents running `splunk/splunk:latest` with ports `8000:8000`, `SPLUNK_PASSWORD`, `SPLUNK_START_ARGS=--accept-license`, and `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com`. It identifies the web UI at `http://host:8000` and login `admin` plus the supplied password. The README notes an additional general-terms acceptance is required for 10.x. This is upstream-documented invocation, not tested here; the operator must personally accept applicable terms. No terms were accepted as part of this research.

For a demo, use the official image rather than adapting the Windows role. A container's distribution is not the VM host distribution: keep the default Debian host preference if otherwise appropriate, but do not infer host compatibility from the image. An upstream throwaway demo command is available in the linked quickstart; it is intentionally not reproduced as a deployment recipe here. For repeatable/production lab use, select and verify a pinned image tag or digest rather than `latest`, and plan persistent data/config volumes, restart policy, and Docker availability. Those operational choices were not researched or tested. Compatibility of a Debian 13 host with Docker and support of any selected image version remain unestablished. Splunk's deprecated Debian container image does **not** establish that Debian hosts are unsupported.

## Native package alternative and evidence limits

A native `.deb` avoids Docker as a runtime layer and may suit a no-container host, but is not as immediately evidenced here as the upstream Docker quickstart. The local Linux detection role's verified-artifact and capability assertions, followed by installation and logging configuration, illustrate why it is not a minimal install path.

The user subsequently supplied a Splunk 10.6 support-table entry listing Debian 13, Ubuntu 24.04, and Ubuntu 26.04 x86_64 as supported. The cited [10.6 system requirements page](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.6/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises?pdfdownload=true) returned 403 and was not independently verified; this updates the earlier OS uncertainty only on a user-supplied basis. Native bootstrap evidence and remaining package/service/terms uncertainties are documented in the follow-up [Ludus Splunk server bootstrap research](ludus-splunk-server-bootstrap.md). The earlier 10.0 Help page and Linux installation page were also attempted but inaccessible/insufficient.

## Recommendation and validation boundary

For the quickest first-start/demo, use the official Splunk Enterprise Docker image quickstart, subject to operator terms acceptance. If Docker is undesirable, native `.deb` is a candidate, pending version-specific verification. A bare server does not require telemetry, apps, or HEC; add those only if the lab requirement calls for them. Findings are static review only: no host inventory, install, deployment, or live validation was performed.
