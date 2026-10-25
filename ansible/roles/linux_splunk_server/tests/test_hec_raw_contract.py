"""Pure-data and source contracts for bounded raw HEC classification.

These tests invoke the production parser/classifier with minimal public config
text. They do not emulate Splunk state, execute commands, or contain captured
guest configuration.
"""

import base64
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

import yaml


if len(sys.argv) != 3:
    raise SystemExit("usage: test_hec_raw_contract.py PARSER PREFLIGHT")

PARSER_PATH = Path(sys.argv[1])
PREFLIGHT_PATH = Path(sys.argv[2])
sys.argv[1:] = []
sys.dont_write_bytecode = True

OWNED_INPUTS = "/opt/splunk/etc/apps/ludus_hec/local/inputs.conf"
OWNED_INDEXES = "/opt/splunk/etc/apps/ludus_hec/local/indexes.conf"
SYSTEM_INPUTS = "/opt/splunk/etc/system/default/inputs.conf"
SYSTEM_SHA256 = "fcb600230352a948926eca671905bb5a4218b927340f5242e30d2dd842a3c9fe"
BUILTIN_INPUTS = "/opt/splunk/etc/apps/splunk_httpinput/default/inputs.conf"
BUILTIN_SHA256 = "524100c61a7f1640366d86b78ead077f03a5c09e83dd2a60a74ce11cbf155f3d"
SECRET = "01234567-89ab-cdef-0123-456789abcdef"


def load_parser():
    if not PARSER_PATH.is_file():
        raise AssertionError(f"missing explicit production parser: {PARSER_PATH}")
    spec = importlib.util.spec_from_file_location("hec_raw_parser_under_test", PARSER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load production parser: {PARSER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def raw_result(source, text):
    return {"source": source, "content": base64.b64encode(text.encode()).decode()}


def classify(parser, parsed, trusted=None):
    arguments = (
        parsed, OWNED_INPUTS, OWNED_INDEXES, SYSTEM_INPUTS,
        "ludus-container-logs", SECRET, ["container_logs"], 8088, True, "",
    )
    if trusted is None:
        return parser.raw_conflicts(*arguments)
    return parser.raw_conflicts(*arguments, trusted_vendor_inputs=trusted)


class HecRawContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = load_parser()

    def verified(self, parsed, expected):
        self.assertTrue(hasattr(self.parser, "verified_vendor_sources"),
                        "production parser lacks content-bound vendor verification")
        return self.parser.verified_vendor_sources(parsed, expected)

    def test_indexes_leading_globals_preserve_provenance_without_index_ownership(self):
        source = "/opt/splunk/etc/system/default/indexes.conf"
        parsed = self.parser.parse_raw_files([raw_result(source, """\
# Minimal syntax from the selected package specification.
maxTotalDataSizeMB = 500000
frozenTimePeriodInSecs = 188697600
[other_index]
homePath = $SPLUNK_DB/other/db
""")])
        self.assertEqual(parsed["errors"], [])
        self.assertEqual(parsed["records"][:2], [
            {"source": source, "stanza": "", "key": "maxTotalDataSizeMB",
             "key_lower": "maxtotaldatasizemb", "value": "500000", "line": 2},
            {"source": source, "stanza": "", "key": "frozenTimePeriodInSecs",
             "key_lower": "frozentimeperiodinsecs", "value": "188697600", "line": 3},
        ])
        self.assertEqual(classify(self.parser, parsed), [])

    def test_explicit_stanzas_remain_authoritative_and_malformed_syntax_still_fails(self):
        explicit = self.parser.parse_raw_files([raw_result(
            "/admin/local/indexes.conf",
            "[container_logs]\nhomePath = $SPLUNK_DB/container_logs/db\n")])
        self.assertEqual(explicit["errors"], [])
        self.assertTrue(any("external requested index stanza" in item
                            for item in classify(self.parser, explicit)))

        malformed = self.parser.parse_raw_files([
            raw_result("/admin/local/indexes.conf", "not an assignment\n[broken\n"),
            raw_result("/admin/local/inputs.conf", "disabled = 0\n"),
        ])
        self.assertGreaterEqual(len(malformed["errors"]), 3)
        self.assertTrue(all("malformed" in item for item in malformed["errors"]))

    def test_vendor_exemption_requires_exact_path_and_content_and_keeps_token_guard(self):
        vendor_text = "[http]\ndisabled = 1\n"
        digest = hashlib.sha256(vendor_text.encode()).hexdigest()
        parsed = self.parser.parse_raw_files([raw_result(BUILTIN_INPUTS, vendor_text)])
        trusted = self.verified(parsed, {BUILTIN_INPUTS: digest})
        self.assertEqual(trusted, [BUILTIN_INPUTS])
        self.assertEqual(classify(self.parser, parsed, trusted), [])

        effective_inputs = self.parser.parse_btool(
            f"{BUILTIN_INPUTS} [http] disabled = 1\n")
        effective_indexes = self.parser.parse_btool(
            "/opt/splunk/etc/system/default/indexes.conf [other_index] homePath = other/db\n")
        effective = self.parser.preflight_effective_conflicts(
            effective_inputs, effective_indexes, OWNED_INPUTS, OWNED_INDEXES,
            SYSTEM_INPUTS, "ludus-container-logs", SECRET, ["container_logs"],
            8088, True, "", trusted_vendor_inputs=trusted)
        self.assertEqual(effective, [])

        modified = self.parser.parse_raw_files([
            raw_result(BUILTIN_INPUTS, vendor_text + "# local modification\n")])
        self.assertEqual(self.verified(modified, {BUILTIN_INPUTS: digest}), [])
        self.assertTrue(any("incompatible shared HEC disabled" in item
                            for item in classify(self.parser, modified)))

        arbitrary = "/opt/splunk/etc/apps/arbitrary/default/inputs.conf"
        arbitrary_parsed = self.parser.parse_raw_files([raw_result(arbitrary, vendor_text)])
        self.assertEqual(self.verified(arbitrary_parsed, {BUILTIN_INPUTS: digest}), [])
        self.assertTrue(any("incompatible shared HEC disabled" in item
                            for item in classify(self.parser, arbitrary_parsed)))

        token_text = vendor_text + f"[http://other]\ntoken = {SECRET}\n"
        token_parsed = self.parser.parse_raw_files([raw_result(BUILTIN_INPUTS, token_text)])
        token_digest = hashlib.sha256(token_text.encode()).hexdigest()
        token_trusted = self.verified(token_parsed, {BUILTIN_INPUTS: token_digest})
        result = "\n".join(classify(self.parser, token_parsed, token_trusted))
        self.assertIn("external HEC token value reuse", result)
        self.assertNotIn(SECRET, result)

    def test_legacy_vendor_argument_cannot_trust_modified_system_default_raw_bytes(self):
        vendor_text = "[http]\ndisabled = 1\n"
        digest = hashlib.sha256(vendor_text.encode()).hexdigest()
        exact = self.parser.parse_raw_files([raw_result(SYSTEM_INPUTS, vendor_text)])
        trusted = self.verified(exact, {SYSTEM_INPUTS: digest})
        self.assertEqual(trusted, [SYSTEM_INPUTS])
        self.assertEqual(classify(self.parser, exact, trusted), [])

        modified = self.parser.parse_raw_files([
            raw_result(SYSTEM_INPUTS, vendor_text + "# modified after packaging\n")])
        self.assertEqual(self.verified(modified, {SYSTEM_INPUTS: digest}), [])
        conflicts = classify(self.parser, modified)
        self.assertTrue(any("incompatible shared HEC disabled" in item
                            for item in conflicts),
                        "legacy vendor_inputs path granted raw trust without matching bytes")

    def test_legacy_vendor_argument_cannot_trust_unverified_effective_system_source(self):
        effective_inputs = self.parser.parse_btool(
            f"{SYSTEM_INPUTS} [http] disabled = 1\n")
        effective_indexes = self.parser.parse_btool(
            "/opt/splunk/etc/system/default/indexes.conf [other_index] homePath = other/db\n")
        arguments = (
            effective_inputs, effective_indexes, OWNED_INPUTS, OWNED_INDEXES,
            SYSTEM_INPUTS, "ludus-container-logs", SECRET, ["container_logs"],
            8088, True, "",
        )
        unverified = self.parser.preflight_effective_conflicts(
            *arguments, trusted_vendor_inputs=())
        self.assertTrue(any("incompatible shared HEC disabled" in item
                            for item in unverified),
                        "legacy vendor_inputs path granted effective trust without verified bytes")

        trusted = self.parser.preflight_effective_conflicts(
            *arguments, trusted_vendor_inputs=[SYSTEM_INPUTS])
        self.assertEqual(trusted, [])

    def test_preflight_pins_selected_vendor_digest_for_raw_and_effective_classification(self):
        try:
            tasks = yaml.safe_load(PREFLIGHT_PATH.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            self.fail(f"cannot load production preflight YAML: {exc}")
        self.assertIsInstance(tasks, list)
        source = yaml.safe_dump(tasks, sort_keys=True)
        for fragment in (
            "system/default/inputs.conf",
            SYSTEM_SHA256,
            "apps/splunk_httpinput/default/inputs.conf",
            BUILTIN_SHA256,
            "splunk_hec_verified_vendor_sources",
            "splunk_server_hec_verified_vendor_inputs",
        ):
            self.assertIn(fragment, source)
        self.assertGreaterEqual(source.count("splunk_server_hec_verified_vendor_inputs"), 3,
                                "verified vendor source must feed raw and effective classifiers")
        raw_carriers = (
            "Read all Splunk input and index definitions",
            "Parse every raw Splunk input and index stanza",
        )
        for name in raw_carriers:
            with self.subTest(raw_carrier=name):
                matches = [task for task in tasks if task.get("name") == name]
                self.assertEqual(len(matches), 1,
                                 f"expected exactly one raw confidentiality carrier: {name}")
                self.assertIs(matches[0].get("no_log"), True,
                              f"raw confidentiality carrier must use no_log: {name}")
        provenance_assertions = [task for task in tasks
                                 if task.get("name") ==
                                 "Require exact selected vendor input provenance"]
        self.assertEqual(len(provenance_assertions), 1)
        provenance_text = yaml.safe_dump(provenance_assertions[0], sort_keys=True)
        self.assertIn("system/default/inputs.conf", provenance_text)
        self.assertIn("apps/splunk_httpinput/default/inputs.conf", provenance_text)


if __name__ == "__main__":
    unittest.main()
