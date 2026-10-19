# Static product pin provenance

`product-pins.yml` records static input facts acquired on 2026-10-18. It does
not claim guest compatibility, installation success, service readiness, chart
rendering, telemetry delivery, target capacity, or deployment readiness.

## Selected inputs

- GitLab CE `19.4.2-ce.0` and Runner `19.4.1-1`: signed package repository
  `InRelease`/`Packages` metadata and the packagecloud primary key fingerprint
  were inspected. Selected GitLab source tag `v19.4.2-ee` resolves to commit
  `9c053f678a4924425869b1b9e4bca3a44e45edf7`.
- Runner authorization: selected-version source and request specs establish
  `create_runner`, `manage_runner`, and conventional PAT scope `read_api`.
  `read_runner` is the route's granular permission and is **not** minted as a
  PAT scope. The selected routes are `/api/v4/user/runners`,
  `/api/v4/runners/all`, `/api/v4/runners/:id`, and
  `/api/v4/runners/:id/jobs`. GitLab readiness uses `/-/readiness`.
- Docker `28.5.2` closure: exact `docker-ce`, CLI, containerd, Buildx, and
  Compose Debian 12 records are pinned from Docker's signed Bookworm metadata.
- Minikube `1.37.0`, kubectl `1.34.1`, Helm `3.19.0`, OTEL Contrib `0.136.0`,
  and OTEL chart `0.80.0`: selected bytes were SHA-256 bound and archive member
  layouts inspected. Chart `0.80.0` retains the default contrib repository
  expected by the existing values template.
- Splunk Enterprise and Universal Forwarder `10.6.1.1` build `b2ae2962645c`,
  and Laurel `0.6.3`: acquired bytes were hash-bound. Debian controls,
  maintainer scripts, launchers, bootstrap seed, first-start, and generated-unit
  expectations were inspected statically.
- Malcolm stays on the role's existing upstream `v26.08.0` commit
  `07bbccdfe2732fb5c5147070cdfca2857b85bacc`.
- Packaged role collections are exact: `ansible.posix==2.2.2` and
  `community.crypto==3.5.0`, selected from Galaxy metadata compatible with the
  pinned Ansible test toolchain.

Detailed acquisition URLs, hashes, archive inspections, signed metadata, and
limitations are retained in the Task 8 implementation report and the local
static acquisition record. Runtime gates remain explicitly separate.

`verified-inputs.yml` schema v2 records these selected facts as the approved
initial static contract. The GitLab readiness route, Runner jobs route, and
forwarder bootstrap entries are named `*_contract` deliberately: their static
shape is verified, while guest readiness, zero jobs, first start, and generated
unit state remain pending provisioning or post-provisioning observations.
