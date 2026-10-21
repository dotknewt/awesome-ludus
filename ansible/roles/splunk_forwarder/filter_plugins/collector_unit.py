"""Pure allowlist parser for the vendor-generated forwarder unit commands."""

from __future__ import annotations

import shlex
import posixpath
import re
import unicodedata


_MAIN = ["/opt/splunkforwarder/bin/splunk", "_internal_launch_under_systemd"]
_CHOWN = {"/bin/chown", "/usr/bin/chown"}
_CHOWN_TARGETS = {
    "/opt/splunkforwarder",
    "/sys/fs/cgroup/cpu/system.slice/%n",
    "/sys/fs/cgroup/memory/system.slice/%n",
    "/sys/fs/cgroup/cpu/system.slice/SplunkForwarder.service",
    "/sys/fs/cgroup/memory/system.slice/SplunkForwarder.service",
}
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
_MONITOR_PATH = re.compile(r"/[A-Za-z0-9_./-]+")
_SOURCETYPE = re.compile(r"[A-Za-z0-9_.:-]+")
_INDEX = re.compile(r"[A-Za-z0-9_.-]+")
_USERNAME = re.compile(r"[A-Za-z0-9_.-]+")


def _literal_match(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None and not any(
        unicodedata.category(character) == "Cc" for character in value
    )


def valid_receiver_host(value: object) -> bool:
    return _literal_match(_HOST, value)


def valid_monitor_path(value: object) -> bool:
    if not _literal_match(_MONITOR_PATH, value) or value == "/":
        return False
    if "..." in value or posixpath.normpath(value) != value:
        return False
    if any(part in {".", ".."} for part in value.split("/")[1:]):
        return False
    return True


def valid_sourcetype(value: object) -> bool:
    return _literal_match(_SOURCETYPE, value)


def valid_index(value: object) -> bool:
    return _literal_match(_INDEX, value)


def valid_username(value: object) -> bool:
    return _literal_match(_USERNAME, value)


def _argv(value: str) -> list[str] | None:
    """Parse one literal command, accepting only systemd's '-' prefix."""
    value = value.strip()
    if value.startswith(("+", "!")):
        return None
    if value.startswith("-"):
        value = value[1:].lstrip()
        if value.startswith(("+", "!")):
            return None
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return None


def _allowed_chown(argv: list[str] | None) -> bool:
    if argv is None:
        return False
    if len(argv) == 4:
        command = argv
    elif len(argv) == 3 and argv[0] in {"/bin/bash", "/usr/bin/bash"} and argv[1] == "-c":
        shell_text = argv[2]
        # Only literal command words, path punctuation, and whitespace are
        # accepted; shell control/expansion/quoting cannot reach the lexer.
        if not shell_text or any(
            not (character.isascii() and (character.isalnum() or character in "_./:%- \t"))
            for character in shell_text
        ):
            return False
        try:
            command = shlex.split(shell_text, posix=True)
        except ValueError:
            return False
        if len(command) != 4:
            return False
    else:
        return False

    executable, recursive, identity, target = command
    return (
        executable in _CHOWN | {"chown"}
        and recursive == "-R"
        and identity == "splunkfwd:splunkfwd"
        and target in _CHOWN_TARGETS
    )


def validate_forwarder_unit_execs(unit_text: str) -> bool:
    """Require one exact main ExecStart and only documented nonroot chowns."""
    main: list[list[str] | None] = []
    hooks: list[list[str] | None] = []
    for line in unit_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key == "ExecStart":
            main.append(_argv(value))
        elif key in {"ExecStartPre", "ExecStartPost"}:
            hooks.append(_argv(value))

    if len(main) != 1 or main[0] != _MAIN:
        return False
    return all(_allowed_chown(argv) for argv in hooks)


class FilterModule:
    def filters(self):
        return {
            "ludus_splunk_collector_validate_forwarder_unit_execs": validate_forwarder_unit_execs,
            "ludus_splunk_collector_valid_receiver_host": valid_receiver_host,
            "ludus_splunk_collector_valid_monitor_path": valid_monitor_path,
            "ludus_splunk_collector_valid_sourcetype": valid_sourcetype,
            "ludus_splunk_collector_valid_index": valid_index,
            "ludus_splunk_collector_valid_username": valid_username,
        }
