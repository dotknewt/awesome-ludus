# Windows UF management-interface provenance

**Research date:** 2026-10-21. This is a bounded documentation search only;
no guest reads, Splunk commands, configuration changes, or service mutations
were performed. The observed diagnostic JSON is treated as parent-owned
evidence, not reinterpreted here.

## Retrieved primary-source excerpts

Firecrawl developer search returned the current official Splunk page **“server.conf”**
(last updated 2026-09-28):
<https://help.splunk.com/en/?resourceId=Splunk_Admin_Serverconf>

Exact returned snippets:

* `disableDefaultPort = <boolean>` — “If set to `true`, turns off listening on
  the splunkd management port, which is 8089 by default.”
* `mgmtMode = none|auto|tcp` — “Sets the transport layer ...”
* The same result says the IPC address “can be either a TCP/IP network port or
  a Unix Domain Sockets (UDS) socket”.

The search result is current official content, but it did not expose the full
stanza context or a Windows-specific applicability statement. Do not treat the
ellipsis in the returned `mgmtMode` snippet as a complete definition.

Firecrawl also returned official **“About management mode for the universal
forwarder”** pages:

* UF 10.0: <https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/10.0/working-with-the-universal-forwarder/about-management-mode-for-the-universal-forwarder>
* UF 9.4: <https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/9.4/working-with-the-universal-forwarder/about-management-mode-for-the-universal-forwarder>

Exact returned snippets from those pages:

* “You can configure how the universal forwarder communicates, either through
  Transmission Control Protocol (TCP) or Unix Domain Sockets (UDS).”
* “Navigate to the server.conf file in the `$SPLUNK_HOME/etc/system/local/`
  folder. Set the `mgmtMode` parameter to your desired mode. Restart the ...”
* The 9.4 result says to check the applicable configuration using
  `disableDefaultPort|mgmtMode`.

These are official UF 10.0/9.4 snippets, not retrieved UF 10.6-specific page
text. They establish documented management-mode knobs, but **do not establish
that UDS is supported or usable on Windows**, nor that a particular Windows UF
10.6.1.1 build defaults to UDS.

An official current `server.conf` result also returned the statement that when
`disableDefaultPort` is true, “only CLI commands that can be run offline are
available for use on the instance.” This supports the consequence of disabling
the default listener, but does not document an HTTPS readiness probe that works
without the listener.

## Version/default conclusions

* The current official `server.conf` search result explicitly states the
  default management port is 8089 and exposes `disableDefaultPort`; its result
  does not identify a UF-versus-Enterprise split in the excerpt.
* The retrieved UF management-mode documentation is versioned 10.0 and 9.4;
  it documents `mgmtMode` values and TCP/UDS as alternatives, but not Windows
  support details. No retrieved official 10.6/10.6.1.1 excerpt establishes
  the Windows default for `mgmtMode`, `disableDefaultPort`, or UDS/named pipes.
* Therefore the observed absence of 8089/8088 cannot be attributed from these
  sources to a specific default, Windows UDS behavior, or the installer flags.
  It remains a target-state question.

## Least-invasive next inspection (not performed or authorized here)

Before considering any enablement, the minimal nonsecret configuration scope
to inspect is the effective `server.conf` `[httpServer]` settings for
`disableDefaultPort`, `mgmtMode`, and any management listener/address setting,
with source-layer provenance (`etc/system/default`, `etc/system/local`, and
app layers). This is an inspection target, not an implementation instruction.

The sources found do not document a loopback-only management configuration for
this Windows UF build, and do not justify enabling network-wide 8089. They also
do not provide a documented non-network HTTPS replacement for validating the
fresh admin bootstrap. Parent approval is required before any such inspection
or functional test.

## Unknowns retained for parent

### Later authorized installed-file observation

At 2026-10-21T05:51:09Z–05:51:12Z, the read-only management probe completed
with `changed=0`, `failed=0`, exit `0`. Evidence:
`/tmp/opencode/splunk-auth-diagnostics-20261021/management-observed.json`
and `management-execution.txt`. The installed `server.conf.spec` documents
`[httpServer] disableDefaultPort` default `false` and `mgmtMode` default `auto`;
the latter describes CLI use of `$SPLUNK_HOME/var/run/splunk/cli.socket` and
conditional TCP fallback where UDS is unsupported. These are bundled-file
observations, not a retrieved Windows-specific support statement. No explicit
assignment of either key was found in the inspected system/app `server.conf`
candidates. This is not an effective-configuration or runtime-transport result;
neither Windows UDS use nor the reason for the absent TCP listener is established.

1. Exact 10.6.1.1 Windows defaults and installer effects for `mgmtMode` and
   `disableDefaultPort`.
2. Whether UF 10.6.1.1 on Windows supports UDS/named pipes for splunkd
   management, and the exact Windows endpoint/configuration if so.
3. Whether the fresh `user-seed.conf` admin bootstrap can be verified through a
   documented offline/loopback mechanism when network management is disabled.
4. Whether the observed service/PID/listener state is consistent with any of
   the documented modes; no inference is made from timestamps or log keyword
   counts.

## 2026-10-21 read-only evidence and Windows reparse-point provenance

Parent-provided read-only evidence in
`/tmp/opencode/splunk-auth-diagnostics-20261021/management-observed.json` and
`socket-errors-observed.json` records: installed `server.conf.spec`
`[httpServer] disableDefaultPort` default `false`; `mgmtMode` default `auto`,
with CLI over `$SPLUNK_HOME/var/run/splunk/cli.socket` and TCP fallback where
UDS is unsupported and the port is enabled; no explicit values in the 11
searched system/app candidates; and `cli.socket` present as a zero-length
`Archive,ReparsePoint`. The evidence does not include the reparse tag, a
successful endpoint connection, or proof that the path is an AF_UNIX socket
rather than another reparse object. The service was running but no TCP 8089
listener was observed. These are observations, not a selected-version
functional verification.

### Microsoft evidence

The bounded Firecrawl developer search retrieved Microsoft Learn's **fsutil**
page: <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil>.
Exact excerpt: `fsutil reparsepoint` “Queries or deletes reparse points”; the
page describes reparse points as NTFS objects with a definable attribute and
user-controlled data. The more specific Microsoft-published command page,
**fsutil reparsepoint**, is
<https://github.com/microsoftdocs/windowsserverdocs/blob/df4a1fb351fb500a61da8ccb162665b3952ef59c/WindowsServerDocs/administration/windows-commands/fsutil-reparsepoint.md>;
its exact excerpt says `query` “Retrieves the reparse point data” for the
specified file/directory. This supports a read-only tag/data query without
following the endpoint or connecting to the socket.

Microsoft's **File system reparse points** documentation,
<https://github.com/microsoftdocs/windows-driver-docs/blob/3aed2ca9f3624d431cba4e74b74e2e7284edf718/windows-driver-docs-pr/ifs/reparse-points.md>,
states that a reparse point contains a tag uniquely identifying the owning
filter/driver and that opening one causes the filesystem to seek the filter
associated with that tag. It does not, in the retrieved excerpt, name
`IO_REPARSE_TAG_AF_UNIX` or prove that this specific path has that tag.

Microsoft search results also returned a WSL release-note excerpt saying AF_UNIX
allows sockets between Linux WSL processes and Windows native processes:
<https://learn.microsoft.com/en-us/windows/wsl/release-notes>. That is not
evidence that Splunk's Windows UF uses AF_UNIX, nor that Windows UF's
`cli.socket` is supported by the UDS mode.

Thus, the legitimate smallest next evidence action is a read-only
`fsutil reparsepoint query` of the exact path, recording the tag/data and
command status without opening/connecting to the endpoint. No code change is
authorized. The role's recursive rejection of all reparse points could reject
a legitimate AF_UNIX socket during convergence, but that is a code-path risk
only; do not weaken that guard until the tag and actual socket semantics are
established.

### Numeric tag identification (bounded follow-up)

The previously cited Microsoft page is now directly retrieved HTTP 200:
**Reparse Point Tags - Win32 apps**,
<https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags>
(Microsoft Learn metadata: updated 2025-03-12; page metadata date
2023-05-01). Exact excerpts:

* “To retrieve the reparse point tag, use the `FindFirstFile` function. If the
  `dwFileAttributes` member includes the `FILE_ATTRIBUTE_REPARSE_POINT`
  attribute, then the `dwReserved0` member specifies the reparse point.”
* “The following are Microsoft's predefined reparse tag values; they are
  defined in WinNT.h: `IO_REPARSE_TAG_AF_UNIX` ...”

The Microsoft WinSDK header is directly retrieved HTTP 200 at the Microsoft
`win32metadata` repository:
<https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h>
(repository `microsoft/win32metadata`, branch `main`; retrieval date
2026-10-21). The header's `IO_REPARSE_TAG_AF_UNIX` definition is the primary
numeric constant source: **`0x80000023L`**. This establishes the name/value
mapping only. It does not establish that any particular `cli.socket` path has
that tag, that the path is a live socket, or that Splunk REST/authentication
works through it.

The same Microsoft page says reparse tags are DWORDs and that the low 16 bits
identify the reparse-point kind. Therefore a read-only `fsutil reparsepoint
query <exact cli.socket path>` result reporting `0x80000023` can be identified
as `IO_REPARSE_TAG_AF_UNIX`; a result showing only `Archive,ReparsePoint`, a
zero length, or a generic reparse attribute is insufficient. The official
`fsutil reparsepoint` command page is
<https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-reparsepoint>;
its exact syntax is `fsutil reparsepoint [query] <filename>` and its `query`
operation “Retrieves the reparse point data”.

## Updated selected-version status

The installed spec observation is direct evidence about this installation's
bundled specification, but it is not an official public 10.6.1.1 documentation
excerpt. Official retrieved UF 10.0/9.4 text documents TCP/UDS management modes;
it does not establish Windows support details or a documented loopback-only
HTTPS setting. No source found here supports broad 8089 enablement, a
`SPLUNK_BINDIP` change, or a PowerShell/.NET socket client. In particular, do
not infer that PS 5.1/.NET Framework exposes a usable `UnixDomainSocketEndPoint`
for this purpose.
