"""Pure-data format/schema checks for the production HEC parser.

The text fixtures exercise documented Splunk conf and ``btool --debug`` record
shapes. They do not run or emulate Splunk, Ansible, handlers, or host state and
are not evidence of native precedence, convergence, or readiness.
"""

import base64
import importlib.util
from pathlib import Path
import sys
import unittest


PARSER_PATH = Path(sys.argv[1]) if len(sys.argv) == 2 else None
sys.argv[1:] = []
sys.dont_write_bytecode = True


def load_parser():
    if PARSER_PATH is None:
        raise AssertionError("supply exactly one explicit parser path")
    if not PARSER_PATH.is_file():
        raise AssertionError(f"missing production parser: {PARSER_PATH}")
    spec = importlib.util.spec_from_file_location("hec_config_under_test", PARSER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load production parser: {PARSER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def raw_result(source, text):
    return {"source": source, "content": base64.b64encode(text.encode()).decode()}


OWNED_INPUTS = "/opt/splunk/etc/apps/ludus_hec/local/inputs.conf"
OWNED_INDEXES = "/opt/splunk/etc/apps/ludus_hec/local/indexes.conf"
VENDOR_INPUTS = "/opt/splunk/etc/system/default/inputs.conf"
SECRET = "01234567-89ab-cdef-0123-456789abcdef"


class HecParserStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = load_parser()

    def test_repeated_raw_stanzas_are_all_retained(self):
        text = """\
[http]
disabled = 1
[http]
disabled = 0
[http://other]
token = different
"""
        parsed = self.parser.parse_raw_files([raw_result("/admin/local/inputs.conf", text)])
        self.assertEqual(parsed["errors"], [])
        self.assertEqual([item["stanza"] for item in parsed["stanzas"]],
                         ["http", "http", "http://other"])
        self.assertEqual([item["value"] for item in parsed["records"][:2]], ["1", "0"])

    def test_external_token_name_and_value_reuse_are_both_rejected_without_secret(self):
        text = f"""\
[http://ludus-container-logs]
token = different
[http://other-name]
token = {SECRET}
"""
        parsed = self.parser.parse_raw_files([raw_result("/admin/local/inputs.conf", text)])
        conflicts = self.parser.raw_conflicts(
            parsed, OWNED_INPUTS, OWNED_INDEXES, VENDOR_INPUTS,
            "ludus-container-logs", SECRET, ["container_logs"], 8088, True, "")
        result = "\n".join(conflicts)
        self.assertIn("token stanza name reuse", result)
        self.assertIn("token value reuse", result)
        self.assertNotIn(SECRET, result)

    def test_split_and_combined_btool_records_keep_stanza_key_value_and_source(self):
        # Split shape: a source/stanza header followed by source/key/value lines.
        # Combined shape: source, stanza, key, and value on one provenance line.
        text = """\
/admin/local/inputs.conf [http]
/admin/local/inputs.conf disabled = 0
/owned/local/inputs.conf [http] port = 8088
"""
        parsed = self.parser.parse_btool(text)
        self.assertEqual(parsed["errors"], [])
        self.assertEqual(parsed["records"], [
            {"source": "/admin/local/inputs.conf", "stanza": "http",
             "key": "disabled", "key_lower": "disabled", "value": "0", "line": 2},
            {"source": "/owned/local/inputs.conf", "stanza": "http",
             "key": "port", "key_lower": "port", "value": "8088", "line": 3},
        ])

    def test_malformed_btool_provenance_is_reported(self):
        parsed = self.parser.parse_btool(
            "/admin/local/inputs.conf disabled = 0\n"
            "/admin/local/inputs.conf malformed provenance\n")
        self.assertEqual(len(parsed["errors"]), 2)
        self.assertIn("setting before source stanza", parsed["errors"][0])
        self.assertIn("unparsed provenance line", parsed["errors"][1])

    def test_effective_contract_requires_exact_source_correlation_without_secret(self):
        inputs_text = f"""\
{OWNED_INPUTS} [http]
{OWNED_INPUTS} disabled = 0
{OWNED_INPUTS} port = 8088
{OWNED_INPUTS} enableSSL = true
{OWNED_INPUTS} [http://ludus-container-logs]
{OWNED_INPUTS} disabled = 0
{OWNED_INPUTS} token = {SECRET}
{OWNED_INPUTS} index = container_logs
{OWNED_INPUTS} indexes = container_logs
"""
        indexes_text = f"""\
{OWNED_INDEXES} [container_logs]
{OWNED_INDEXES} homePath = $SPLUNK_DB/container_logs/db
{OWNED_INDEXES} coldPath = $SPLUNK_DB/container_logs/colddb
{OWNED_INDEXES} thawedPath = $SPLUNK_DB/container_logs/thaweddb
"""
        indexes = self.parser.parse_btool(indexes_text)
        valid = self.parser.effective_conflicts(
            self.parser.parse_btool(inputs_text), indexes, OWNED_INPUTS, OWNED_INDEXES,
            "ludus-container-logs", SECRET, ["container_logs"], "container_logs",
            8088, True, "")
        self.assertEqual(valid, [])

        wrong_source = inputs_text.replace(
            f"{OWNED_INPUTS} token =", "/admin/local/inputs.conf token =")
        conflicts = self.parser.effective_conflicts(
            self.parser.parse_btool(wrong_source), indexes, OWNED_INPUTS, OWNED_INDEXES,
            "ludus-container-logs", SECRET, ["container_logs"], "container_logs",
            8088, True, "")
        result = "\n".join(conflicts)
        self.assertIn("unexpected source", result)
        self.assertNotIn(SECRET, result)


if __name__ == "__main__":
    unittest.main()
