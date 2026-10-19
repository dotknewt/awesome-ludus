# Reviewed Debian Bookworm stock-log profile

These files are exact bytes frozen from the URLs and package versions recorded
in `manifest.json`. They were copied from the approved, hash-verified
`reference-inputs/` workspace; the helper performs no source or network fetch.

The rsyslog and logrotate files retain their upstream licensing and copyright
terms as distributed by Debian. The corresponding Debian source packages are
`rsyslog` 8.2302.0-1, `logrotate` 3.21.0-1, `apt` 2.6.1 and `dpkg` 1.21.23.
See those source packages' `debian/copyright` files for complete license text.

`rsyslog.service.reference` is provenance for the reviewed expected invocation
only. It is intentionally not a target profile file and does not establish the
identity of a running unit; runtime identity is observed through systemd and
`/proc` by the helper.
