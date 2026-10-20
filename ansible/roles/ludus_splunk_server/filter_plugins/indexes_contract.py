"""Pure validation and parsing helpers for the separately owned index app."""

import configparser
import json
import re


_INDEX_NAME = re.compile(r"[a-z][a-z0-9_]{0,79}")
_RESERVED = {
    "main", "history", "summary", "default", "internal",
    "_internal", "_audit", "_introspection", "_metrics",
    "_metrics_rollup", "_telemetry", "_configtracker", "_thefishbucket",
}
_HEADER = re.compile(r"^\s*\[([^\]\r\n]+)\]\s*(?:[#;].*)?$")
_DATA_ROOT = "/opt/splunk/var/lib/splunk"


def _parse_indexes_conf(configuration):
    """Parse strictly, preserving option case and rejecting DEFAULT inheritance."""
    if not isinstance(configuration, str):
        return None
    try:
        configuration.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    if "\x00" in configuration:
        return None
    for line in configuration.splitlines():
        header = _HEADER.fullmatch(line)
        if header and header.group(1).strip().casefold() == "default":
            return None

    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        empty_lines_in_values=False,
    )
    parser.optionxform = str
    try:
        parser.read_string(configuration)
    except (configparser.Error, UnicodeError, ValueError):
        return None
    if parser.defaults():
        return None
    return parser


def _parse_external_indexes_conf(configuration):
    """Strictly parse vendor config while accepting Splunk's global syntax.

    Splunk permits global assignments before any stanza and a lowercase
    ``[default]`` stanza. A collision-proof synthetic ConfigParser default
    section captures headerless assignments without changing the source text
    used by stanza collision discovery. The uppercase ConfigParser ``[DEFAULT]``
    sentinel remains rejected to avoid implicit inheritance ambiguity.
    """
    if not isinstance(configuration, str):
        return None
    try:
        configuration.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    if "\x00" in configuration:
        return None

    section_names = []
    for line in configuration.splitlines():
        header = _HEADER.fullmatch(line)
        if header:
            name = header.group(1).strip()
            if name.casefold() == "default" and name != "default":
                return None
            section_names.append(name)

    synthetic_section = "__LUDUS_SPLUNK_EXTERNAL_GLOBAL__"
    while synthetic_section in section_names:
        synthetic_section += "_"
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        empty_lines_in_values=False,
    )
    parser.optionxform = str
    parser.default_section = synthetic_section
    try:
        parser.read_string(f"[{synthetic_section}]\n{configuration}")
    except (configparser.Error, UnicodeError, ValueError):
        return None
    return parser


def indexes_valid(value):
    """Return whether value is a unique list of supported non-reserved names."""
    if not isinstance(value, list):
        return False
    seen = set()
    for name in value:
        if not isinstance(name, str) or _INDEX_NAME.fullmatch(name) is None:
            return False
        if name in _RESERVED or name.startswith("_") or name in seen:
            return False
        seen.add(name)
    return True


def index_stanzas(configuration):
    """Discover every explicit section header, preserving duplicate names.

    This intentionally does not use ConfigParser: strict managed-config parsing
    rejects duplicate sections, but collision discovery must still see each
    header in an unmanaged file. Full parseability is checked separately and
    fails closed before this result can authorize a write.
    """
    if not isinstance(configuration, str):
        raise ValueError("indexes.conf content is not decoded text")
    try:
        configuration.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError("indexes.conf content is not valid UTF-8 text") from error
    if "\x00" in configuration:
        raise ValueError("indexes.conf content contains a NUL byte")
    return [
        match.group(1).strip()
        for line in configuration.splitlines()
        if (match := _HEADER.fullmatch(line)) is not None
    ]


def index_config_parseable(configuration):
    """Validate external Splunk config syntax, including supported global forms."""
    return _parse_external_indexes_conf(configuration) is not None


def marker_matches_config(marker_text, configuration):
    """Require the authoritative marker and managed config to agree exactly."""
    try:
        marker = json.loads(marker_text)
    except (TypeError, ValueError):
        return False
    if not isinstance(marker, dict) or type(marker.get("schema_version")) is not int or marker["schema_version"] != 1:
        return False
    if set(marker) != {"schema_version", "indexes"}:
        return False
    names = marker.get("indexes")
    if not indexes_valid(names) or not names:
        return False
    parser = _parse_indexes_conf(configuration)
    if parser is None or set(parser.sections()) != set(names):
        return False
    for name in names:
        expected = {
            "homePath": f"{_DATA_ROOT}/{name}/db",
            "coldPath": f"{_DATA_ROOT}/{name}/colddb",
            "thawedPath": f"{_DATA_ROOT}/{name}/thaweddb",
        }
        if dict(parser.items(name, raw=True)) != expected:
            return False
    return True


def marker_allows_append(marker_text, requested):
    """An existing managed list may grow but may never lose any prior index."""
    try:
        marker = json.loads(marker_text)
    except (TypeError, ValueError):
        return False
    if not isinstance(marker, dict) or type(marker.get("schema_version")) is not int or marker["schema_version"] != 1:
        return False
    if set(marker) != {"schema_version", "indexes"}:
        return False
    owned = marker.get("indexes")
    return bool(owned) and indexes_valid(owned) and indexes_valid(requested) and set(owned).issubset(set(requested))


class FilterModule:
    def filters(self):
        return {
            "ludus_splunk_server_indexes_valid": indexes_valid,
            "ludus_splunk_server_index_stanzas": index_stanzas,
            "ludus_splunk_server_index_config_parseable": index_config_parseable,
            "ludus_splunk_server_index_marker_matches_config": marker_matches_config,
            "ludus_splunk_server_index_marker_allows_append": marker_allows_append,
        }
