"""Bounded parsers and contract checks for the role-owned Splunk HEC app."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets


_BTOOL_COMBINED = re.compile(
    r"^(?P<source>.+?\.conf)\s+\[(?P<stanza>[^]]+)]\s+"
    r"(?P<key>[^=]+?)\s*=\s*(?P<value>.*)$"
)
_BTOOL_HEADER = re.compile(r"^(?P<source>.+?\.conf)\s+\[(?P<stanza>[^]]+)]$")
_BTOOL_SETTING = re.compile(
    r"^(?P<source>.+?\.conf)\s+(?P<key>[^=]+?)\s*=\s*(?P<value>.*)$"
)


def _record(source, stanza, key, value, line):
    return {
        "source": source,
        "stanza": stanza.strip(),
        "key": key.strip(),
        "key_lower": key.strip().lower(),
        "value": value.strip(),
        "line": line,
    }


def _parse_raw(text, source):
    records, stanzas, errors = [], [], []
    stanza = None
    before_first_stanza = True
    for number, raw_line in enumerate(str(text).splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            before_first_stanza = False
            if not line.endswith("]") or len(line) < 3:
                errors.append(f"{source}:{number}: malformed stanza header")
                stanza = None
            else:
                stanza = line[1:-1].strip()
                stanzas.append({"source": source, "stanza": stanza, "line": number})
            continue
        if "=" not in line:
            errors.append(f"{source}:{number}: malformed setting")
            continue
        key, value = line.split("=", 1)
        if not key.strip():
            errors.append(f"{source}:{number}: empty setting name")
            continue
        if stanza is None:
            is_indexes_file = source == "indexes.conf" or source.endswith("/indexes.conf")
            if before_first_stanza and is_indexes_file:
                records.append(_record(source, "", key, value, number))
            else:
                errors.append(f"{source}:{number}: malformed setting")
            continue
        records.append(_record(source, stanza, key, value, number))
    return records, stanzas, errors


def parse_raw_files(slurp_results):
    parsed = {"records": [], "stanzas": [], "errors": [], "files": []}
    for result in slurp_results or []:
        if result.get("skipped"):
            continue
        source = result.get("source", "<unknown>")
        try:
            raw = base64.b64decode(result.get("content", ""), validate=True)
            text = raw.decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            parsed["errors"].append(f"{source}: unreadable UTF-8/base64: {exc}")
            continue
        parsed["files"].append({"source": source, "sha256": hashlib.sha256(raw).hexdigest()})
        records, stanzas, errors = _parse_raw(text, source)
        parsed["records"].extend(records)
        parsed["stanzas"].extend(stanzas)
        parsed["errors"].extend(errors)
    return parsed


def verified_vendor_sources(parsed, expected_path_to_sha256):
    """Return exact source paths whose parsed raw bytes match pinned digests."""
    verified = []
    files = parsed.get("files", [])
    for source, expected in (expected_path_to_sha256 or {}).items():
        matches = [item for item in files if item.get("source") == source]
        if len(matches) == 1 and secrets.compare_digest(
                str(matches[0].get("sha256", "")), str(expected)):
            verified.append(source)
    return sorted(verified)


def parse_btool(text):
    parsed = {"records": [], "stanzas": [], "errors": []}
    seen = set()
    current_stanza = None
    for number, raw_line in enumerate(str(text).splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        match = _BTOOL_COMBINED.match(line)
        if match:
            values = match.groupdict()
            source, stanza = values["source"], values["stanza"]
            current_stanza = stanza
            record = _record(source, stanza, values["key"], values["value"], number)
            parsed["records"].append(record)
            identity = (source, stanza)
            if identity not in seen:
                parsed["stanzas"].append({"source": source, "stanza": stanza, "line": number})
                seen.add(identity)
            continue
        match = _BTOOL_HEADER.match(line)
        if match:
            values = match.groupdict()
            source, stanza = values["source"], values["stanza"].strip()
            current_stanza = stanza
            identity = (source, stanza)
            if identity not in seen:
                parsed["stanzas"].append({"source": source, "stanza": stanza, "line": number})
                seen.add(identity)
            continue
        match = _BTOOL_SETTING.match(line)
        if not match:
            if ".conf" in line or ("[" in line and "]" in line):
                parsed["errors"].append(f"btool:{number}: unparsed provenance line")
            continue
        values = match.groupdict()
        source = values["source"]
        if current_stanza is None:
            parsed["errors"].append(f"btool:{number}: setting before source stanza")
            continue
        record = _record(source, current_stanza, values["key"], values["value"], number)
        parsed["records"].append(record)
        # Inherited settings retain their source without declaring a stanza there.
    return parsed


def _same(left, right, boolean=False):
    if boolean:
        aliases = {"1": "true", "yes": "true", "on": "true", "0": "false", "no": "false", "off": "false"}
        left = aliases.get(str(left).strip().lower(), str(left).strip().lower())
        right = aliases.get(str(right).strip().lower(), str(right).strip().lower())
    return secrets.compare_digest(str(left), str(right))


def raw_conflicts(parsed, owned_inputs, owned_indexes, vendor_inputs, token_name,
                  token_value, indexes, port, ssl_enabled, server_cert,
                  trusted_vendor_inputs=()):
    conflicts = list(parsed.get("errors", []))
    expected_http = {
        "disabled": ("0", True),
        "port": (str(port), False),
        "enablessl": (str(bool(ssl_enabled)).lower(), True),
    }
    if server_cert:
        expected_http["servercert"] = (server_cert, False)
    token_stanza = f"http://{token_name}"
    for stanza in parsed.get("stanzas", []):
        is_inputs = stanza["source"].endswith("inputs.conf")
        is_indexes = stanza["source"].endswith("indexes.conf")
        if is_inputs and stanza["source"] != owned_inputs and stanza["stanza"] == token_stanza:
            conflicts.append(f"external token stanza name reuse: {stanza['source']}")
        if is_indexes and stanza["source"] != owned_indexes and stanza["stanza"] in indexes:
            conflicts.append(f"external requested index stanza: {stanza['source']} [{stanza['stanza']}]")
    for record in parsed.get("records", []):
        source, stanza, key = record["source"], record["stanza"], record["key_lower"]
        if source.endswith("inputs.conf") and source != owned_inputs and stanza.startswith("http://") and key == "token":
            if _same(record["value"], token_value):
                conflicts.append(f"external HEC token value reuse: {source} [{stanza}]")
        if (not source.endswith("inputs.conf")
                or source == owned_inputs
                or source in trusted_vendor_inputs
                or stanza != "http" or key not in expected_http):
            continue
        expected, boolean = expected_http[key]
        if not _same(record["value"], expected, boolean):
            conflicts.append(f"incompatible shared HEC {key}: {source} [{stanza}]")
    return conflicts


def preflight_effective_conflicts(inputs, indexes_parsed, owned_inputs, owned_indexes,
                                  vendor_inputs, token_name, token_value, index_names,
                                  port, ssl_enabled, server_cert,
                                  trusted_vendor_inputs=()):
    combined = {
        "records": inputs.get("records", []) + indexes_parsed.get("records", []),
        "stanzas": inputs.get("stanzas", []) + indexes_parsed.get("stanzas", []),
        "errors": inputs.get("errors", []) + indexes_parsed.get("errors", []),
    }
    conflicts = raw_conflicts(combined, owned_inputs, owned_indexes, vendor_inputs,
                               token_name, token_value, index_names, port, ssl_enabled,
                               server_cert, trusted_vendor_inputs)
    if not inputs.get("records"):
        conflicts.append("pre-write btool inputs output contained no parsed records")
    if not indexes_parsed.get("records"):
        conflicts.append("pre-write btool indexes output contained no parsed records")
    return conflicts


def _require(records, stanza, key, expected, sources, label, csv=False):
    matches = [item for item in records if item["stanza"] == stanza and item["key_lower"] == key.lower()]
    if len(matches) != 1:
        return [f"{label}: expected one effective [{stanza}] {key}, found {len(matches)}"]
    record = matches[0]
    if record["source"] not in sources:
        return [f"{label}: unexpected source for [{stanza}] {key}: {record['source']}"]
    actual = record["value"]
    if csv:
        actual = ",".join(part.strip() for part in actual.split(","))
        expected = ",".join(part.strip() for part in str(expected).split(","))
    if not _same(actual, expected, key.lower() in ("disabled", "enablessl")):
        return [f"{label}: wrong effective value for [{stanza}] {key}"]
    return []


def effective_conflicts(inputs, indexes_parsed, owned_inputs, owned_indexes,
                        token_name, token_value, index_names, default_index,
                        port, ssl_enabled, server_cert):
    conflicts = list(inputs.get("errors", [])) + list(indexes_parsed.get("errors", []))
    input_records = inputs.get("records", [])
    global_sources = {item["source"] for item in input_records if item["source"] != owned_inputs}
    global_sources.add(owned_inputs)
    global_sources = {source for source in global_sources if "/system/default/" not in source}
    for key, value in (("disabled", "0"), ("port", str(port)),
                       ("enableSSL", str(bool(ssl_enabled)).lower())):
        conflicts.extend(_require(input_records, "http", key, value, global_sources, "listener"))
    if server_cert:
        conflicts.extend(_require(input_records, "http", "serverCert", server_cert,
                                  global_sources, "listener"))
    token_stanza = f"http://{token_name}"
    for key, value, csv in (("disabled", "0", False), ("token", token_value, False),
                            ("index", default_index, False),
                            ("indexes", ",".join(index_names), True)):
        conflicts.extend(_require(input_records, token_stanza, key, value,
                                  {owned_inputs}, "token", csv))
    index_records = indexes_parsed.get("records", [])
    for index in index_names:
        for key, suffix in (("homePath", "db"), ("coldPath", "colddb"),
                            ("thawedPath", "thaweddb")):
            expected = f"$SPLUNK_DB/{index}/{suffix}"
            conflicts.extend(_require(index_records, index, key, expected,
                                      {owned_indexes}, f"index {index}"))
    return conflicts


def _effective_boolean(records, stanza, key, default, label, conflicts):
    matches = [item for item in records
               if item["stanza"] == stanza and item["key_lower"] == key.lower()]
    if not matches:
        return default
    if len(matches) != 1:
        conflicts.append(f"{label}: expected at most one effective {key} record")
        return None
    normalized = str(matches[0]["value"]).strip().lower()
    aliases = {"1": True, "true": True, "yes": True, "on": True,
               "0": False, "false": False, "no": False, "off": False}
    if normalized not in aliases:
        conflicts.append(f"{label}: effective {key} has unsupported boolean shape")
        return None
    return aliases[normalized]


def _effective_port(records, stanza, key, label, conflicts):
    matches = [item for item in records
               if item["stanza"] == stanza and item["key_lower"] == key.lower()]
    if not matches:
        conflicts.append(f"{label}: expected one effective port record, found 0")
        return None
    if len(matches) != 1:
        conflicts.append(f"{label}: expected one effective port record, found {len(matches)}")
        return None
    value = matches[0]["value"].strip()
    match = re.search(r"(?:^|:)([0-9]{1,5})$", value)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        conflicts.append(f"{label}: effective listener port has unsupported shape")
        return None
    return int(match.group(1)), matches[0]["source"]


def non_hec_listener_conflicts(inputs, server, web, hec_port, receiving_port,
                               management_port, web_port):
    """Return known non-HEC listener collisions without returning raw values."""
    conflicts = (list(inputs.get("errors", [])) + list(server.get("errors", []))
                 + list(web.get("errors", [])))
    declared = {
        "receiving": receiving_port,
        "management": management_port,
        "web": web_port,
    }
    for label, port in declared.items():
        try:
            matches_hec = int(hec_port) == int(port)
        except (TypeError, ValueError):
            conflicts.append(f"{label}: declared listener port is not numeric")
            continue
        if matches_hec:
            conflicts.append(f"HEC port collides with declared Splunk {label} port")

    input_records = inputs.get("records", [])
    receiving_prefixes = ("splunktcp://", "splunktcp-ssl://",
                          "splunktcp:", "splunktcp-ssl:")
    receiving_stanzas = sorted({item["stanza"] for item in inputs.get("stanzas", [])
                                if item["stanza"].startswith(receiving_prefixes)})
    for stanza in receiving_stanzas:
        disabled = _effective_boolean(input_records, stanza, "disabled", False,
                                      "receiving", conflicts)
        if disabled is None or disabled:
            continue
        prefix = next(item for item in receiving_prefixes if stanza.startswith(item))
        endpoint = stanza[len(prefix):]
        match = re.search(r"(?:^|:)([0-9]{1,5})$", endpoint)
        if not match or not 1 <= int(match.group(1)) <= 65535:
            conflicts.append("receiving: effective listener stanza has unsupported port shape")
            continue
        if int(match.group(1)) == int(hec_port):
            sources = sorted({item["source"] for item in input_records if item["stanza"] == stanza})
            source = sources[0] if sources else "<stanza provenance only>"
            conflicts.append(f"HEC port collides with effective Splunk receiving listener: {source}")

    server_records = server.get("records", [])
    web_records = web.get("records", [])
    default_port_disabled = _effective_boolean(
        server_records, "httpServer", "disableDefaultPort", False,
        "management", conflicts)
    if default_port_disabled is False:
        management = _effective_port(web_records, "settings", "mgmtHostPort",
                                     "management", conflicts)
        if management and management[0] == int(hec_port):
            conflicts.append(f"HEC port collides with effective Splunk management listener: {management[1]}")

    web_enabled = _effective_boolean(web_records, "settings", "startwebserver",
                                     True, "web", conflicts)
    if web_enabled is True:
        effective_web = _effective_port(web_records, "settings", "httpport",
                                       "web", conflicts)
        if effective_web and effective_web[0] == int(hec_port):
            conflicts.append(f"HEC port collides with effective Splunk web listener: {effective_web[1]}")
    return conflicts


class FilterModule:
    def filters(self):
        return {
            "splunk_hec_parse_raw_files": parse_raw_files,
            "splunk_hec_verified_vendor_sources": verified_vendor_sources,
            "splunk_hec_parse_btool": parse_btool,
            "splunk_hec_raw_conflicts": raw_conflicts,
            "splunk_hec_preflight_effective_conflicts": preflight_effective_conflicts,
            "splunk_hec_effective_conflicts": effective_conflicts,
            "splunk_hec_non_hec_listener_conflicts": non_hec_listener_conflicts,
        }
