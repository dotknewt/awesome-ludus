# Detection Engineering range

`range-config.yml` is the canonical, populated Ludus range
configuration. It contains all five VMs, the selected product pins and role
inputs, VLAN 10 addresses, and the approved 108 GB / 26-vCPU graph. Its only
application credentials are the user-approved lab-default Splunk and Malcolm
credentials, reusing the Debian `debian:debian` machine login. These weak values
are intentionally explicit in the public machine configuration at the user's
request; they are not production-safe.
Writing or saving this file is not deployment authorization, and runtime
acceptance remains pending.

The official Ludus schema fetched on 2026-10-19 accepts `ludus_extensions` and
documents that it is ignored by Ludus and exposed to Ansible. The extension in
this file records review and lifecycle information; it is not an enforcement
boundary. `range-config.draft.yml` is a superseded source snapshot retained for
prior-review provenance and is not referenced by `blueprint.yml`.

## Guarded materialization

Target facts and protected application values are separate inputs. To render a
fresh public, secret-free copy without requiring deployment facts:

```bash
python3 blueprints/detection-engineering/materialize.py \
  --mode public-save \
  --target-inputs blueprints/detection-engineering/target-inputs.thrunt-draft.yml \
  --output /secure/path/thrunt-save-review.yml
```

To render the credential-bearing file that may be saved to the already
authorized `thrunt` range, use the protected input directly and keep the output
outside the repository:

```bash
python3 blueprints/detection-engineering/materialize.py \
  --mode private-save \
  --target-inputs blueprints/detection-engineering/target-inputs.thrunt-draft.yml \
  --protected-inputs ~/.config/ludus/detection-engineering/thrunt-bootstrap.yml \
  --output ~/.config/ludus/detection-engineering/thrunt-range.yml
```

`public-save` and `private-save` enforce the exact graph, role/collection names,
selected pins, target identity/network shape, and protected-input schema. They
record unknown architecture, inherited disk, free RAM, allocations, timestamps,
and runtime acceptance as informational unresolved execution facts rather than
artificial file-writing gates. `private-save` does not claim deployment
eligibility. Deployment mode remains separate and additionally requires
complete typed deployment evidence plus the protected input. Output is
created without clobbering an existing path and with mode `0600`; if the final
directory fsync fails after linking, the command reports `PUBLICATION UNCERTAIN`
and the operator must inspect the output path before retrying. Generating output
does not authorize apply/deployment or establish runtime compatibility.

Execution eligibility is phased. Initial provisioning requires the selected static
product contract, complete template metadata, capacity/sufficiency, Ludus range
networking, and protected application inputs. Required role/collection names are
still validated as dependency names, but the user explicitly waived installed
role-version and content comparison on 2026-10-19. The waiver is recorded as
`USER_WAIVED_NOT_VERIFIED`; it is not a verified-content claim.
The existing `debian` account and HOME, guest capture interface, selected-product
installation/bootstrap, and native producers are checked during provisioning
after a guest exists. External service/API state, Runner pause and zero jobs,
telemetry/packet delivery, and credential cleanup are post-provisioning runtime
acceptance; they are never prerequisites for a `NEVER_DEPLOYED` range and are
not marked `VERIFIED` without live evidence.

As of 2026-10-18, guest OS and guest Docker firewall rules are explicitly out
of scope. This blueprint does not wire `ludus_detection_guest_firewall`, emit
`detection_firewall_*` variables, or require ingress CIDRs, probe sources,
Docker bridge discovery, service-port allowlists, or firewall isolation
acceptance. The standalone role remains available for other consumers.

## Current facts and choices

Read-only authenticated API observations recorded on 2026-10-18 show range
`thrunt` is number 3, `NEVER DEPLOYED`, has zero VMs, and testing disabled.
The user supplied the range network `10.3.0.0/16`, approved VLAN-10 lab subnet
`10.3.10.0/24`, and host bridge `vmbr3`. Host-bridge promiscuous mode is a
manual user action, not a configuration/provisioning blocker, and `vmbr3` is
not a guest capture interface. Free RAM/current allocations and a reviewed sufficiency
decision remain unresolved. The host has 128 GB total RAM by user report (not
128 GB free); the API reported 16 cores and the recorded storage pools.
Template inventory included Debian 12, Debian 13, and Debian 13.5 server
`debian-12-x64-server-template`, `debian-13-x64-server-template`, and
`debian-13.5-x64-server-no-template`. The controller selected
`debian-12-x64-server-template` for all five as a candidate
because it matches the known Bookworm logging profile; availability is not
OS/role compatibility evidence.

The documented Debian template login is `debian:debian` per
<https://docs.ludus.cloud/docs/using-ludus/passwords/> and was selected by the
user. The configuration reuses `debian` with `/home/debian`; workload and
Malcolm roles do not create that login or change its password. The separate
`deotel` collector account remains a non-login system account.

Splunk and Malcolm application admins are also explicitly named `debian` and
use the same lab password. Splunk's 10.6.1.1 bundled
`authentication.conf.spec` documents default `minPasswordLength = 8` and the
`[splunk_auth]` override. The role stages `minPasswordLength = 6` only for the
first bootstrap start alongside `user-seed.conf`, then removes that temporary
policy file in cleanup; this permits the six-character requested password
without leaving a persistent relaxation. The role's standalone default admin
username remains `admin`.

| VM | RAM | CPUs | VLAN | IP suffix | Template |
|---|---:|---:|---:|---:|---|
| gitlab | 8 GB | 4 | 10 | 11 | Debian 12 candidate |
| runner | 8 GB | 4 | 10 | 12 | Debian 12 candidate |
| malcolm | 64 GB | 8 | 10 | 13 | Debian 12 candidate |
| splunk | 12 GB | 4 | 10 | 14 | Debian 12 candidate |
| workload | 16 GB | 6 | 10 | 15 | Debian 12 candidate |

Requested resources total 108 GB RAM and 26 vCPUs. Per user direction, the
128 GB host reserves the remaining 20 GB for the hypervisor and does not reserve
space for other VMs. Free RAM, current allocations, overhead, inherited template
disk sizes, and deployment sufficiency remain unresolved execution facts; they
do not prevent writing or saving the configuration. Four hosts include
the explicit `acl`, audit, repository, Python, logrotate, and rsyslog prerequisites;
Malcolm owns its package lifecycle. This does not fabricate telemetry
events. The intended roles and native Laurel/forwarder scope are represented,
but draft values remain incomplete. GitLab, runner, and workload use the
project `ludus_detection_forwarder_pipeline`; runner and producer roles express
peer dependencies through Ludus `depends_on`. Splunk uses the project
`ludus_detection_splunk`, never the remote legacy collector as a substitute.
The Universal Forwarder version/build/URL, digest, and static bootstrap contract
are assigned only to the three pipeline hosts. Enterprise Splunk has its own
independently acquired digest. Neither static record proves first-start success.

The existing 108 GB / 26-vCPU graph is unchanged: GitLab 8/4, Runner 8/4,
Malcolm 64/8, Splunk 12/4, and workload 16/6.

GitLab keeps the package-generated root credential at
`/etc/gitlab/initial_root_password`; this blueprint neither supplies nor resets,
deletes, copies, or publishes it. The local protected-input schema contains only
the Splunk and Malcolm admin passwords, Malcolm admin username, and the HEC
desired-state marker. Runner bootstrap and HEC token values remain role-owned
and are not pre-generated.

The generated `thrunt` protected input is stored outside the repository at
`~/.config/ludus/detection-engineering/thrunt-bootstrap.yml` (parent `0700`,
file `0600`). The private-save renderer reads it without printing values and
writes `~/.config/ludus/detection-engineering/thrunt-range.yml` at mode `0600`.
The canonical file explicitly contains the user-approved known machine-default
application values. The protected input/private save files are retained at mode
`0600` outside the repository, and no prior generated random credential values
are included in repository evidence.
No Ansible-controller path is projected onto the remote GitLab server.

## Required before execution

- Required role and collection names must remain present. Installed role versions
  and contents are intentionally not compared under the recorded user waiver;
  Debian 12 runtime compatibility remains unverified. Remote legacy roles are
  not substitutes or aliases, and no testing override is set.
- Before deployment, obtain inherited template disk and architecture, free
  RAM/current allocations, and a reviewed sufficiency decision. Malcolm's capture interface is resolved
  during provisioning rather than fabricated as initial evidence.
- The currently selected package, artifact, Git, chart, readiness-route,
  Runner-route, forwarder-bootstrap, and OTEL contracts are statically acquired
  and reusable. Revalidate and re-approve them only if those selected facts
  change; obtain all external secrets through an approved protected mechanism.
- Verify selected Laurel and every other product on the actual Debian template;
  static checksum/layout evidence is not guest ABI or service acceptance.
- Exercise the role-internal Splunk-local logging seam after package/account
  creation and before Splunk bootstrap on a disposable authorized guest.
- Confirm planned 108 GB RAM / 26 vCPU allocations plus overhead and storage.

No configuration was changed remotely; no roles were uploaded, and no range
was deployed or applied. Local materialization and a future controller-owned
remote save are distinct from deployment authorization and runtime acceptance.
