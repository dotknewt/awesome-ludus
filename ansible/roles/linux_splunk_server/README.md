# linux_splunk_server

Installs Splunk Enterprise on Linux for Ludus ranges and configures its
receiving port. The role keeps its existing role identity and installation
lifecycle.

## Shared inputs

Set values common to the server and forwarders once in range-level
`global_role_vars`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_version` | `10.6.1.1` | Splunk release |
| `splunk_build` | `b2ae2962645c` | Splunk release build |
| `splunk_accept_license` | `false` | Must be explicitly `true` before the role runs |
| `splunk_receiver_port` | `9997` | Receiver port configured for forwarders |

The false license default is intentional. The role asserts explicit acceptance
before any existing task, including installation or configuration.

## Server-only inputs

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_server_download_token` | empty | Optional download token |
| `splunk_server_install_dir` | `/opt` | Installation parent directory |
| `splunk_server_home` | `/opt/splunk` | Existing installation/configuration home |
| `splunk_server_admin_user` | `admin` | Server administrator username |
| `splunk_server_admin_password` | `Changeme1!` | Server administrator password |
| `splunk_server_web_port` | `8000` | Web UI port |
| `splunk_server_mgmt_port` | `8089` | Management port |
| `splunk_server_license_file` | empty | Optional license file path |
| `splunk_server_enable_boot_start` | `true` | Enable systemd boot start |
| `splunk_server_disable_popups` | `true` | Disable first-login UI tours |

## Optional owned HEC app

HEC management is opt-in and scoped to one marked app under
`{{ splunk_server_home }}/etc/apps/{{ splunk_server_hec_app }}`. The role does
not publish credentials as facts and does not configure collectors. Callers
must map the endpoint, index, and token explicitly into each collector role.

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_server_hec_enabled` | `false` | Manage the owned HEC app |
| `splunk_server_hec_validate` | `false` | Send one authenticated acceptance event after convergence |
| `splunk_server_hec_app` | `ludus_hec` | Stable owned app identity |
| `splunk_server_hec_port` | `8088` | HEC listener port |
| `splunk_server_hec_ssl_enabled` | `true` | Use Splunk's shared management/HEC TLS setting |
| `splunk_server_hec_server_cert` | empty | Optional existing certificate path readable by Splunk |
| `splunk_server_hec_token_name` | `ludus-container-logs` | Stable owned token stanza name |
| `splunk_server_hec_token` | empty | Required caller-supplied token when enabled |
| `splunk_server_hec_indexes` | `[]` | Required unique indexes owned by this app |
| `splunk_server_hec_default_index` | empty | Required member of the owned index list |
| `splunk_server_hec_validation_endpoint` | empty | Exact reachable `/services/collector/event` URL required for validation |
| `splunk_server_hec_validate_certs` | `true` | Verify the validation endpoint certificate |
| `splunk_server_hec_ca_path` | empty | Optional CA bundle on the Splunk/validation host |

Example role variables (use an external secret mechanism for the token):

```yaml
splunk_server_hec_enabled: true
splunk_server_hec_app: ludus_hec
splunk_server_hec_token_name: ludus-container-logs
splunk_server_hec_token: "{{ externally_supplied_hec_token }}"
splunk_server_hec_indexes:
  - container_logs
splunk_server_hec_default_index: container_logs
splunk_server_hec_validate: true
splunk_server_hec_validation_endpoint: https://splunk.example.test:8088/services/collector/event
splunk_server_hec_validate_certs: true
splunk_server_hec_ca_path: /etc/ssl/certs/lab-ca.pem
```

Preflight uses the bounded role-local `filter_plugins/hec_config.py` parser to
inventory every raw stanza in every on-disk `inputs.conf`/`indexes.conf`,
including repeated definitions that lose precedence, and to correlate each
`btool --debug` stanza/key/value with its source file. Vendor defaults may be
overridden. Compatible administrator-managed global listener values may be
shared, but incompatible listener values, external reuse of either the token
stanza name or secret token value, requested indexes defined outside the owned
app, cluster-peer context, unmarked paths, and ownership identity changes fail
before write. App, token-name, or index-set migration is intentionally not
automatic. Parser findings never include the token value and all token-bearing
classification remains under `no_log`.

Owned directories use mode `0700`; markers and configuration use `0600` and the
observed running Splunk identity. Token-bearing operations suppress logs and
diffs. Normal runs render protected candidates and compare them with active
files. When replacement is required, a protected pending-restart intent is
persisted before either active file is replaced. Each post-write expected value
is then correlated with its exact effective stanza and source before the HEC
restart topic is notified. A failed replacement or effective check retains the
pending marker and never flushes a newly queued restart. The marker remains
through restart and process/TCP readiness, carrying interruption forward to the
next successful run. An unchanged rerun with no pending marker performs no
HEC-triggered restart. The legacy and HEC notification topics share one handler
pair, so one flush cannot restart Splunk twice.

After any verified restart, process and TCP listener readiness are checked.
These readiness checks are not authenticated ingestion and do not establish
searchability. Optional validation sends one identified event with the configured
token and index and requires both HTTP 200 and parsed HEC JSON code `0`. It proves
HEC acceptance only—not indexing/searchability, parsing, or end-to-end delivery.
Validation is disabled by default because it writes an event.

Check mode performs preflight and reports a plan without creating files,
restarting Splunk, invoking a mutating Splunk CLI action, or sending an event. It
does not claim that a not-yet-created app is effective. Setting either management
switch back to `false` is cessation of management, not teardown: the role does
not delete indexes/data, remove the app, revoke or rotate tokens, or stop a
listener. Those operations require a separately reviewed migration/removal path.

Example:

```yaml
# Illustrative fragment only; not a complete runnable range config.
# Hostname, template, network, and other VM fields are intentionally omitted.
global_role_vars:
  splunk_version: "10.6.1.1"
  splunk_build: "b2ae2962645c"
  splunk_accept_license: true
  splunk_receiver_port: 9997

ludus:
  - vm_name: "{{ range_id }}-splunk"
    # Replace this example role ID with the identity reported by the target server.
    roles:
      - dotknewt.ludus_splunk_server
    role_vars:
      splunk_server_admin_password: "ReplaceThisLabPassword!"
```

## Role identity and attribution

The source directory is `linux_splunk_server`; metadata declares the role name
`linux_splunk_enterprise`; active examples retain `dotknewt.ludus_splunk_server`
or `ludus_splunk`. The installed identity is **not verified**. Do not infer it
from the directory or metadata: use the identity reported by the target Ludus
server, and update both `roles` and any matching `depends_on.role` references
consistently. No role or example identity is renamed here.

This role was previously supplied through the stale
`curi0usJack/ludus_splunk` Git submodule mapping. The supplied local files declare
MIT (the README's license notice and role metadata); no separate `LICENSE` file
was supplied. The upstream source revision is not established here, and no
provenance audit is claimed. `galaxy_info.author: dotknewt` is maintainer
metadata, not a claim of sole authorship.

## Index configuration limitation

There is no general server index-list input. The existing tasks still create
their hard-coded `wineventlog` and `sysmon` indexes, except that they skip a name
explicitly owned by the enabled HEC app. `splunk_server_hec_indexes` belongs only
to the isolated HEC subflow; an old caller value such as
`ludus_splunk_server_indexes` remains unsupported. Client index names are not
automatically aligned.

The HEC contract was researched for the selected Splunk Enterprise 10.6.1.1 and
fails closed if HEC is requested with another version. HEC convergence does not
repair the role's unrelated license lifecycle: supplying a license still invokes
the existing license task, which swallows its failure. Runtime installation,
precedence behavior, check-mode behavior, restart ordering, and selected-version
compatibility are not established by static checks.
