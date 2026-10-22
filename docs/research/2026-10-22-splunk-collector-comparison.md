# Legacy Splunk collector comparison

Date: 2026-10-22. This is a comparison of exact source and archive bytes, not a
claim of runtime equivalence. No collector was installed or run, and no Splunk
endpoint, guest, or deployment was queried. The four legacy roles remain
unchanged.

## Provenance and inspection boundary

The repository-side comparison used commit
`bd3db4a751ca8281e00a7b858d1f7071d30403a6`. The exact task bytes were:

| Role task | SHA-256 |
| --- | --- |
| `ansible/roles/role_splunk_collector_certer/tasks/main.yml` | `c15f7a99e754f74690584348bf64a3a73be2ebc30cc4560237fec6f07bd5e5b0` |
| `ansible/roles/role_splunk_collector_win11a/tasks/main.yml` | `04de79c5432e5a8d383641fdcf3dd85d9098a5f9d5c50d6bcc87ef4fd245ca32` |
| `ansible/roles/role_splunk_collector_win11v/tasks/main.yml` | `3e42d636f00782b62a52ba07c8b0b67421d32eead9f03592e7e616b1d68f3dba` |
| `ansible/roles/role_splunk_collector_linuxv/tasks/main.yml` | `02719f52a2a8f9bcc22ebf06278e401de8933ee8b96337c28b90618176d5bab0` |

The comparison target was the `splunk_forwarder` tree at that same commit. In
particular, the inspected Windows input template SHA-256 was
`171edfff193bbb2d7521d32eb60ec7157a48b102717704bd7e577d0653d93423`,
the Linux input template SHA-256 was
`3c5329a1396fae72cdf09bcfa7fa7fc4867edc5b176befdf395ad827fa0e1644`,
and its defaults SHA-256 was
`4b4159e2cc18b870e8d268a8ea8d3c550261bed18b28375f0cdbf1003e09fa27`.
These hashes delimit the inspected comparison; later changes would make parity
unknown until separately reviewed.

The three upstream ZIPs were downloaded from immutable commit
`0cefe62755eebba7b226e611ece75160706e22f6`. Archive paths, CRCs, duplicate and
case-collision conditions, path traversal/absolute/drive/ADS names, encryption,
links and non-regular types were checked before read-only extraction. The limits
were 10,000 entries, 128 MiB expanded per archive, 32 MiB per file/download, and
a compression ratio below 1,000. All three passed those bounded checks. Scripts
were read as text and never executed.

| Archive and exact URL | Exact inspected bytes | SHA-256 | Entries / expanded bytes |
| --- | ---: | --- | ---: |
| [`splunkappscerter.zip`](https://raw.githubusercontent.com/Antonlovesdnb/ConstructingDefense/0cefe62755eebba7b226e611ece75160706e22f6/splunkappscerter.zip) | 260,178 | `4235d79ba87ebec09a8c1ab550d9936855b09dd1c19517185fbf6cfebc739c3e` | 94 / 958,757 |
| [`splunkappswin11a.zip`](https://raw.githubusercontent.com/Antonlovesdnb/ConstructingDefense/0cefe62755eebba7b226e611ece75160706e22f6/splunkappswin11a.zip) | 472,049 | `17739d7ed714d691d3338521b7f0574fc9d17b7e4c4d932484322c777abcc840` | 169 / 1,564,680 |
| [`splunkappswin11v.zip`](https://raw.githubusercontent.com/Antonlovesdnb/ConstructingDefense/0cefe62755eebba7b226e611ece75160706e22f6/splunkappswin11v.zip) | 323,794 | `5ae6b8741e91211b80e386d3cf97e8f3f4a19b360bc0960444906c4b9004cea2` | 123 / 1,090,898 |

Supplemental raw inventories and response headers were preserved under
`/tmp/opencode/portable-splunk-gpo/collector-inspection-tuysl242`, including the
three `*-evidence.json` files and `repository-artifact-hashes.json`. The URL,
size, digest, and relevant findings are reproduced here so this document does
not depend on that temporary directory remaining available.

## Active inputs and material differences

The following table describes the merged intent visible in the inspected app
defaults/local files. It does not establish the effective configuration of any
installed Universal Forwarder.

| Legacy role | Inspected active inputs | Material non-equivalence with `splunk_forwarder` |
| --- | --- | --- |
| CERTER | Splunk Add-on for Microsoft Windows **9.0.1**. Local Security input writes to `winlogs`, uses XML rendering, `current_only=0`, `checkpointInterval=5`, and AD object resolution. Two XML regex blacklists target event 5145 C$/ADMIN$ share patterns. | The generic template can select the Security channel and index, but cannot encode these XML rendering, history, checkpoint, AD-resolution, or XML-filter options. It does not distribute the Windows TA. |
| WIN11A | Windows TA **9.0.1**, Splunk Add-on for Microsoft Sysmon **4.0.2**, and PSTree **2.0.0**. Security writes to `winlogs`; Sysmon Operational writes to `sysmon`, with `renderXml=1` and an explicit XML source. Security has the C$ local blacklist; its ADMIN$ local blacklist line is commented. | Channel/index/sourcetype selection does not supply the two TAs, their XML/source settings, props/transforms/lookups, or PSTree. The generic role has no app/script/search-command delivery. |
| WIN11V | Windows TA **9.0.1** and Sysmon TA **4.0.2**, with the same Security/Sysmon configuration as WIN11A. It additionally enables `WinEventLog://SilkService-Log` to index `etw` with sourcetype `json`. It has no PSTree app. | An explicit generic override can name the SILK channel/index/sourcetype, but SILK is not a default and the TA/XML/filter gaps remain. A `json` sourcetype label does not prove extraction of JSON from a Windows event envelope. |
| LinuxV | No app ZIP. Universal Forwarder **9.3.2**, receiver `dc:9997`, and CLI monitor `/var/log/laurel/audit.log` to index `linux`; no sourcetype is set. | The generic role's inspected defaults select UF **10.6.1.1**, index `main`, and sourcetype `laurel:json`, with a configurable receiver and a different package/account/service lifecycle. The path is representable after explicit choices, but an existing 9.3.2 installation is not automatically or safely adopted. |

### Default/local precedence and disabled content

The Windows TA contains 60 default input stanzas and WMI collection stanzas,
but all are disabled in the shipped defaults; the local files enable only the
inputs listed above. Its shipped inventory, listening-port, time-sync, network,
AD/DNS health/replication/site, Windows Update, and BIOS scripts are therefore
present but are not active feeds. The Python
`user_account_control_property` external lookup is a separate search-time
capability.

Local comments do not delete default settings. CERTER replaces both Windows TA
default blacklist keys. WIN11A/WIN11V replace only the first; their commented
local `blacklist2` leaves the TA's default event-566/Object Type rule in effect.
This is why comparing only the local files would overstate similarity.

All three archives contain the Windows TA's default `props.conf` and
`transforms.conf` (152 and 318 stanza headers respectively), including XML and
Windows field extraction, aliases/lookups, WEF host/source transforms, and DHCP
header discard. WIN11A/WIN11V also contain identical Sysmon TA props/transforms
(4 and 29 stanza headers), with event/process/network/registry XML extraction
and CIM aliases/evaluations. The Sysmon TA's WEC input is disabled. Installing
the add-on does not install the Sysmon event producer.

WIN11A places PSTree as `splunk_pstree_app`: `default/commands.conf` invokes
`bin/pstree.py` with Python 3 and the chunked protocol. The script implements a
Splunk process-tree search command and bundles Splunk SDK 1.6.16; it is not a
sensor or collection input. These knowledge objects and PSTree must be assessed
for the appropriate indexer/search-head tier. Their mere presence on a forwarder
does not prove that search-time processing occurred there.

Neither the legacy app inputs nor the generic forwarder defaults subscribe to a
PowerShell Operational channel or monitor `C:\Transcripts`. Thus the separate
logging policy's PowerShell and transcription settings create potential event
sources but do not collect them. No Windows collector in this comparison closes
that gap.

### Lifecycle and ownership are also different

The legacy Windows roles install UF 9.3.2, use mutable app downloads without a
checksum, hardcode receiver `DC:9997` and lab administrator credentials, attempt
LocalSystem service configuration, restart, and disable every firewall profile.
Those side effects are not collection parity requirements. The generic role
uses configurable shared release/receiver/license inputs, retains the installed
service identity, adds Event Log Readers membership, and does not mutate the
firewall. Its source inspection also showed limitations: no MSI digest, disabled
no-token TLS validation, whole-file `system/local/inputs.conf` replacement,
unconditional stop/start when enabled, and swallowed service errors. Static
inspection does not demonstrate clean Windows convergence or safe takeover of
legacy app state.

On Linux, the generic role adds checksum/package validation, a dedicated
non-root systemd lifecycle, and role-owned app checks. The legacy role's CLI
flow does not explicitly run as `splunkfwd` or enable boot start. Neither role
installs Laurel; `/var/log/laurel/audit.log` must already be produced and
readable.

## Licensing and redistribution evidence

At the inspected upstream revision the repository root had no `LICENSE` or
`README`, GitHub repository metadata reported `license: null`, and the collector
ZIPs did not establish one aggregate permissive license. The Windows and Sysmon
TAs include `LICENSES/LicenseRef-Splunk-8-2021.txt`; its section 9 contains
resale/transfer/distribution restrictions except where expressly permitted.
PSTree source headers cite Apache-2.0 and BSD-style psutil-derived logic, but the
extracted PSTree app has no standalone license file and bundles Splunk SDK
1.6.16. The GPLv3 file in each downloader role does not establish redistribution
rights for separately downloaded ZIP bytes. Mirroring or vendoring requires a
separate rights and attribution determination.

## Disposition and unknowns

The four legacy collectors are retained. None is a drop-in equivalent of the
generic `splunk_forwarder`, and this comparison does not request changes to
either family. LinuxV is the nearest feed-level mapping only after explicit
receiver/index/sourcetype and install-state migration decisions. Windows parity
would require richer input options plus an explicit add-on and tier-placement
decision. Disabled scripts are inventory, not mandatory active-feed parity.

Static archive/source inspection cannot establish installed app state, merged
runtime configuration, TA/UF compatibility, service convergence, actual event
production, XML parsing/filtering, field extraction, delivery, index identity,
searchability, persistence, or preservation of unrelated state. If any hashed
role/app artifact differs from the bytes above, equivalence is **unknown**, not
implicitly retained. Deployment readiness remains **PASS WITH WARNINGS — NOT
VERIFIED**.

Primary placement references read on 2026-10-22:

- [Splunk Add-on for Microsoft Windows installation and tier placement](https://splunk.github.io/splunk-add-on-for-microsoft-windows/Install/)
- [Splunk Add-on for Microsoft Windows configuration precedence](https://splunk.github.io/splunk-add-on-for-microsoft-windows/Configuration/)
- [Splunk Add-on for Microsoft Sysmon installation and tier placement](https://splunk.github.io/splunk-add-on-for-microsoft-sysmon/Install/)

These current references support placement guidance; they do not prove archived
TA compatibility with UF 10.6.1.1.
