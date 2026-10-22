"""Bounded parsers and contract checks for the role-owned Splunk HEC app."""

from __future__ import annotations

import base64
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
    for number, raw_line in enumerate(str(text).splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            if not line.endswith("]") or len(line) < 3:
                errors.append(f"{source}:{number}: malformed stanza header")
                stanza = None
            else:
                stanza = line[1:-1].strip()
                stanzas.append({"source": source, "stanza": stanza, "line": number})
            continue
        if stanza is None or "=" not in line:
            errors.append(f"{source}:{number}: malformed setting")
            continue
        key, value = line.split("=", 1)
        if not key.strip():
            errors.append(f"{source}:{number}: empty setting name")
            continue
        records.append(_record(source, stanza, key, value, number))
    return records, stanzas, errors


def parse_raw_files(slurp_results):
    parsed = {"records": [], "stanzas": [], "errors": []}
    for result in slurp_results or []:
        if result.get("skipped"):
            continue
        source = result.get("source", "<unknown>")
        try:
            text = base64.b64decode(result.get("content", ""), validate=True).decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            parsed["errors"].append(f"{source}: unreadable UTF-8/base64: {exc}")
            continue
        records, stanzas, errors = _parse_raw(text, source)
        parsed["records"].extend(records)
        parsed["stanzas"].extend(stanzas)
        parsed["errors"].extend(errors)
    return parsed


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
        identity = (source, current_stanza)
        if identity not in seen:
            parsed["stanzas"].append({"source": source, "stanza": current_stanza, "line": number})
            seen.add(identity)
    return parsed


def _same(left, right, boolean=False):
    if boolean:
        aliases = {"1": "true", "yes": "true", "on": "true", "0": "false", "no": "false", "off": "false"}
        left = aliases.get(str(left).strip().lower(), str(left).strip().lower())
        right = aliases.get(str(right).strip().lower(), str(right).strip().lower())
    return secrets.compare_digest(str(left), str(right))


def raw_conflicts(parsed, owned_inputs, owned_indexes, vendor_inputs, token_name,
                  token_value, indexes, port, ssl_enabled, server_cert):
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
        if (not source.endswith("inputs.conf") or source in (owned_inputs, vendor_inputs)
                or stanza != "http" or key not in expected_http):
            continue
        expected, boolean = expected_http[key]
        if not _same(record["value"], expected, boolean):
            conflicts.append(f"incompatible shared HEC {key}: {source} [{stanza}]")
    return conflicts


def preflight_effective_conflicts(inputs, indexes_parsed, owned_inputs, owned_indexes,
                                  vendor_inputs, token_name, token_value, index_names,
                                  port, ssl_enabled, server_cert):
    combined = {
        "records": inputs.get("records", []) + indexes_parsed.get("records", []),
        "stanzas": inputs.get("stanzas", []) + indexes_parsed.get("stanzas", []),
        "errors": inputs.get("errors", []) + indexes_parsed.get("errors", []),
    }
    conflicts = raw_conflicts(combined, owned_inputs, owned_indexes, vendor_inputs,
                              token_name, token_value, index_names, port, ssl_enabled,
                              server_cert)
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


class FilterModule:
    def filters(self):
        return {
            "splunk_hec_parse_raw_files": parse_raw_files,
            "splunk_hec_parse_btool": parse_btool,
            "splunk_hec_raw_conflicts": raw_conflicts,
            "splunk_hec_preflight_effective_conflicts": preflight_effective_conflicts,
            "splunk_hec_effective_conflicts": effective_conflicts,
        }
