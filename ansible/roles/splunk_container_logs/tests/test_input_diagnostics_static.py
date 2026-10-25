"""Source-only contracts for failure-path input diagnostics."""

import ast
from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).parents[1]
PREFLIGHT = ROLE / "tasks" / "preflight.yml"
PLUGIN = ROLE / "action_plugins" / "splunk_container_logs_input_diagnostics.py"

ORIGINAL_ASSERTIONS = (
    "splunk_container_logs_owner_id is string",
    "splunk_container_logs_owner_id | length > 0",
    "splunk_container_logs_owner_id is match('^[A-Za-z0-9][A-Za-z0-9._-]*$')",
    "splunk_container_logs_hec_endpoint is string",
    "splunk_container_logs_hec_endpoint | length > 0",
    "splunk_container_logs_hec_endpoint | urlsplit('hostname') | length > 0",
    "splunk_container_logs_hec_endpoint | urlsplit('path') == '/services/collector/event'",
    "splunk_container_logs_hec_endpoint | urlsplit('query') | length == 0",
    "splunk_container_logs_hec_endpoint | urlsplit('fragment') | length == 0",
    "splunk_container_logs_hec_endpoint | urlsplit('username') is none",
    "splunk_container_logs_hec_endpoint | urlsplit('password') is none",
    "splunk_container_logs_hec_endpoint.startswith('https://') or (splunk_container_logs_hec_endpoint.startswith('http://') and splunk_container_logs_allow_insecure_http)",
    "splunk_container_logs_hec_index is string",
    "splunk_container_logs_hec_index | length > 0",
    "splunk_container_logs_hec_token is string",
    "splunk_container_logs_hec_token | length > 0 or (splunk_container_logs_mode == 'kubernetes' and splunk_container_logs_k8s_existing_secret | length > 0)",
    "splunk_container_logs_tls_verify is boolean",
    "splunk_container_logs_allow_insecure_http is boolean",
    "splunk_container_logs_ca_file is string",
    "splunk_container_logs_start_at in ['end', 'beginning']",
    "(splunk_container_logs_queue_size | splunk_container_queue_size) is integer",
    "(splunk_container_logs_queue_max_disk_mib | splunk_container_queue_disk_mib) is integer",
    "splunk_container_logs_mode != 'docker' or (splunk_container_logs_collector_url is string and splunk_container_logs_collector_url.startswith('https://'))",
)

CONDITION_NAMES = (
    "owner_id_type", "owner_id_nonempty", "owner_id_pattern",
    "hec_endpoint_type", "hec_endpoint_nonempty", "hec_endpoint_hostname",
    "hec_endpoint_path", "hec_endpoint_no_query", "hec_endpoint_no_fragment",
    "hec_endpoint_no_username", "hec_endpoint_no_password", "hec_endpoint_scheme",
    "hec_index_type", "hec_index_nonempty", "hec_token_type", "hec_token_or_secret",
    "tls_verify_boolean", "allow_insecure_http_boolean", "ca_file_type",
    "start_at_allowed", "queue_size_valid", "queue_disk_valid",
    "collector_url_for_docker",
)

TYPE_VARIABLES = (
    "splunk_container_logs_owner_id", "splunk_container_logs_hec_endpoint",
    "splunk_container_logs_hec_index", "splunk_container_logs_hec_token",
    "splunk_container_logs_mode", "splunk_container_logs_k8s_existing_secret",
    "splunk_container_logs_tls_verify", "splunk_container_logs_allow_insecure_http",
    "splunk_container_logs_ca_file", "splunk_container_logs_start_at",
    "splunk_container_logs_queue_size", "splunk_container_logs_queue_max_disk_mib",
    "splunk_container_logs_collector_url",
)

EXPECTED_TYPE_CODES = {
    "str": "text", "AnsibleUnsafeText": "unsafe_text", "AnsibleUnicode": "unicode_text",
    "bool": "boolean", "int": "integer", "float": "float", "list": "list",
    "dict": "mapping", "NoneType": "null", "tuple": "tuple", "set": "set",
    "AnsibleSequence": "sequence", "AnsibleMapping": "mapping",
    "AnsibleVaultEncryptedUnicode": "vault_text", "AnsibleUndefined": "undefined",
}


def normalized(value):
    return " ".join(str(value).split())


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


class InputDiagnosticsStatic(unittest.TestCase):
    def test_original_validation_is_preserved_inside_failure_only_wrapper(self):
        tasks = yaml.safe_load(PREFLIGHT.read_text(encoding="utf-8"))
        wrapper = next(task for task in tasks if task.get("name") == "Validate shared HEC transport and bounded queue inputs")
        inner = next(
            task for task in wrapper.get("block", [])
            if task.get("name") == "Validate shared HEC transport and bounded queue inputs"
        )
        self.assertEqual(tuple(map(normalized, module(inner, "assert")["that"])), ORIGINAL_ASSERTIONS)
        self.assertEqual(module(inner, "assert")["fail_msg"], (
            "Supply an exact HEC event endpoint, nonempty index/token, explicit HTTP "
            "permission where needed, valid TLS controls, and positive bounded queues."
        ))
        self.assertIs(inner.get("no_log"), True)
        self.assertNotIn("always", wrapper)

        rescue = wrapper["rescue"]
        nested = rescue[0]
        self.assertEqual(list(nested), ["name", "block", "rescue", "always"])
        action = nested["block"][0]
        self.assertEqual(action.get("action"), "splunk_container_logs_input_diagnostics")
        self.assertEqual(action.get("args", {}), {})
        self.assertIs(action.get("no_log"), True)
        self.assertEqual(action.get("register"), "splunk_container_logs_input_diagnostics_result")
        report = nested["block"][1]
        self.assertEqual(module(report, "debug")["msg"],
                         "{{ splunk_container_logs_input_diagnostics_result.report }}")
        self.assertIs(report.get("no_log"), False)
        nested_error = nested["rescue"][0]
        self.assertEqual(module(nested_error, "debug").get("msg"),
                         "Input diagnostics unavailable (evaluation_error).")
        self.assertIs(nested_error.get("no_log"), False)
        self.assertEqual(len(rescue), 1)
        final_failure = nested["always"][0]
        self.assertEqual(module(final_failure, "fail").get("msg"),
                         "Shared HEC input validation failed; no role changes were made.")
        self.assertIs(final_failure.get("no_log"), True)
        self.assertNotIn("when", final_failure)

    def test_diagnostic_plugin_is_fixed_controller_only_and_value_free(self):
        source = PLUGIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        action_class = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ActionModule"
        )
        assignments = {
            target.id: ast.literal_eval(node.value)
            for node in action_class.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id == "_requires_connection"
        }
        self.assertIs(assignments.get("_requires_connection"), False)

        catalogue = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "CONDITION_CATALOGUE"
                    for target in node.targets)
        )
        entries = ast.literal_eval(catalogue.value)
        self.assertEqual(tuple(name for name, _ in entries), CONDITION_NAMES)
        self.assertEqual(tuple(map(normalized, (expression for _, expression in entries))),
                         ORIGINAL_ASSERTIONS)

        type_variables = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "TYPE_VARIABLES"
                    for target in node.targets)
        )
        self.assertEqual(ast.literal_eval(type_variables.value), TYPE_VARIABLES)
        type_codes = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "TYPE_CODES"
                    for target in node.targets)
        )
        self.assertEqual(ast.literal_eval(type_codes.value), EXPECTED_TYPE_CODES)
        self.assertIn("Conditional", source)
        self.assertIn("evaluate_conditional", source)
        self.assertIn("all_vars=task_vars", source)
        self.assertIn("available_variables = task_vars", source)
        aliases_templar = any(
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "templar"
                    for target in node.targets)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
            and node.value.attr == "_templar"
            for node in ast.walk(tree)
        )
        templates_with_templar_alias = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "templar"
            and node.func.attr == "template"
            for node in ast.walk(tree)
        )
        self.assertTrue(aliases_templar and templates_with_templar_alias)
        has_exact_bool_type_guard = any(
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Call)
            and isinstance(node.left.func, ast.Name)
            and node.left.func.id == "type"
            and len(node.left.args) == 1
            and isinstance(node.left.args[0], ast.Name)
            and node.left.args[0].id == "result"
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.IsNot)
            and isinstance(node.comparators[0], ast.Name)
            and node.comparators[0].id == "bool"
            for node in ast.walk(tree)
        )
        self.assertTrue(has_exact_bool_type_guard)
        self.assertNotIn("original_reached", source)
        self.assertNotIn("original_assertion_reaches_next", source)
        self.assertIn("except Exception", source)
        for forbidden in (
            "subprocess", "requests", "urllib", "socket", "open(", "lookup(",
            "run_command", "self._connection", "str(exc)", "repr(exc)", "traceback",
            "super().run", "ansible_failed_result", "bool(", "json.dumps", "json.loads",
        ):
            self.assertNotIn(forbidden, source)
        for unsafe_type in ("AnsibleUnsafeText", "AnsibleUnicode", "NoneType", "bool", "int", "float", "str", "list", "dict"):
            self.assertIn(unsafe_type, source)


if __name__ == "__main__":
    unittest.main()
