"""Static Ludus CLI and capability-boundary contracts; never contacts a server."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

from scripts.ludus_deployment import ludus

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "scripts" / "ludus_deployment" / "ludus.py"


def adapter_tree() -> ast.Module:
    if not ADAPTER.is_file():
        raise AssertionError("required production adapter scripts/ludus_deployment/ludus.py is missing")
    return ast.parse(ADAPTER.read_text(encoding="utf-8"), filename=str(ADAPTER))


def class_node(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"required adapter class {name} is missing")


def source_segment(node: ast.AST) -> str:
    """Extract a class/function's local source from the parsed adapter AST."""
    return ast.get_source_segment(ADAPTER.read_text(encoding="utf-8"), node) or ""


class LudusContractTests(unittest.TestCase):
    def test_adapter_command_shapes_match_research(self):
        """Require literal argv construction matching the pinned CLI contract."""
        tree = adapter_tree()
        expected = {
            "_client_version_argv": ("ludus", "version"),
            "_server_version_argv": ("ludus", "version", "--verbose"),
            "_active_config_argv": ("ludus", "range", "config", "get", "--range", "<range>", "--json"),
            "_status_argv": ("ludus", "range", "status", "--range", "<range>", "--json"),
            "_installed_roles_argv": ("ludus", "ansible", "role", "list", "--range", "<range>", "--json"),
            "_history_list_argv": ("ludus", "range", "logs", "--history", "--range", "<range>", "--json"),
            "_upload_argv": ("ludus", "ansible", "role", "add", "--directory", "<stage>", "--force", "--json"),
            "_launch_roles_argv": ("ludus", "range", "deploy", "--range", "<range>", "--tags", "user-defined-roles", "--json"),
            "_launch_full_argv": ("ludus", "range", "deploy", "--range", "<range>", "--json"),
        }
        found: dict[str, tuple[str, ...]] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in expected:
                values = []
                for item in ast.walk(node):
                    if isinstance(item, (ast.List, ast.Tuple)):
                        literals = [elt.value for elt in item.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
                        if literals:
                            values.append(tuple(literals))
                found[node.name] = max(values, key=len, default=())
        self.assertEqual(set(found), set(expected), "adapter must expose all documented pure argv builders")
        self.assertEqual(found, expected)

    def test_read_client_has_no_mutation_entrypoint(self):
        """Read capability has only documented reads; deploy requires explicit opt-in."""
        tree = adapter_tree()
        read_client = class_node(tree, "_ReadClient")
        methods = {
            node.name
            for node in read_client.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertTrue({"active_config", "status", "installed_roles", "history_list", "observe_history", "observe_run"} <= methods)
        self.assertFalse({"upload", "launch", "deploy", "install", "mutate"} & methods)
        deploy_client = class_node(tree, "DeployClient")
        deploy_methods = {
            node.name
            for node in deploy_client.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertTrue({"upload", "launch"} <= deploy_methods)
        self.assertTrue(any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "enable_deploy"
            for node in tree.body
        ), "mutation capability must be explicitly enabled")

    def test_version_parser_uses_independent_pinned_labels(self):
        """Parse client and verbose server labels, not any matching version token."""
        client, server = ludus._parse_versions(
            "INFO Ludus client 2.3.10+fccf931e\nAnsible version: 1.26.3\n",
            "\x1b[32mINFO\x1b[0m Ludus Server 2.3.10+fccf931e - licensed to example\n",
        )
        self.assertEqual(client, "2.3.10+fccf931e")
        self.assertEqual(server, "2.3.10+fccf931e")
        for text in (
            "INFO Ludus Server 2.3.10+fccf931e - text\nINFO Ludus Server 2.3.11+abcdef12 - text",
            "INFO unrelated component 2.3.10+fccf931e",
        ):
            with self.assertRaises(ludus.LudusAdapterError):
                ludus._parse_versions("INFO Ludus client 2.3.10+fccf931e", text)
        with self.assertRaises(ludus.LudusAdapterError):
            ludus._parse_versions(
                "INFO Ludus client 2.3.10+fccf931e",
                "INFO Ludus Server 2.3.11+abcdef12 - licensed",
            )
        for client_line in (
            "INFO Ludus client 2.3.10+fccf931e-extra",
            "INFO Ludus client 2.3.10+fccf931e.other",
        ):
            with self.subTest(client=client_line), self.assertRaises(ludus.LudusAdapterError):
                ludus._parse_versions(
                    client_line,
                    "INFO Ludus Server 2.3.10+fccf931e - licensed",
                )
        with self.assertRaises(ludus.LudusAdapterError):
            ludus._parse_versions(
                "INFO Ludus client 2.3.11+abcdef12",
                "INFO Ludus Server 2.3.10+fccf931e - licensed",
            )

    def test_settings_defaults_and_environment_precedence_are_pinned(self):
        """Resolve documented URL/TLS defaults and treat empty environment as unset."""
        resolve = ludus._resolve_settings
        self.assertEqual(
            resolve({}, {}),
            ("https://198.51.100.1:8080", "", False),
        )
        self.assertEqual(
            resolve({"LUDUS_URL": "", "LUDUS_PROXY": "", "LUDUS_VERIFY": ""},
                    {"url": "https://configured.invalid:8080", "proxy": "http://proxy.invalid", "verify": True}),
            ("https://configured.invalid:8080", "http://proxy.invalid", True),
        )
        self.assertEqual(
            resolve({"LUDUS_URL": "https://env.invalid:8080", "LUDUS_VERIFY": "false"},
                    {"url": "https://configured.invalid:8080", "verify": True}),
            ("https://env.invalid:8080", "", False),
        )
        with self.assertRaises(ludus.LudusAdapterError):
            resolve({"LUDUS_USER": "other"}, {"user": "other"})
        for malformed in ({"url": False}, {"proxy": []}):
            with self.subTest(config=malformed), self.assertRaises(ludus.LudusAdapterError):
                resolve({}, malformed)

    def test_range_id_rejects_cli_query_and_flag_injection(self):
        """Range IDs are validated before being passed to the CLI's query argument."""
        for bad in ("x&userID=ROOT", "x?foo=1", "x#frag", "x/y", "x=y", "--help", "x%26y"):
            with self.subTest(value=bad), self.assertRaises(ludus.LudusAdapterError):
                ludus._validate_range_id(bad)
        self.assertEqual(ludus._validate_range_id("lab-01"), "lab-01")

    def test_capture_path_is_bounded_without_disk_or_preexec(self):
        """Capture must be bounded while draining both pipes; never spill raw output to disk."""
        capture = next(node for node in adapter_tree().body if isinstance(node, ast.FunctionDef) and node.name == "_capture_process")
        source = source_segment(capture)
        self.assertNotIn("tempfile", source)
        self.assertNotIn("preexec_fn", source)
        self.assertNotIn("communicate(", source)
        self.assertIn("selectors", source)
        self.assertIn("PIPE", source)
        self.assertEqual(sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr == "Popen" for node in ast.walk(capture)), 1)

    def test_mutation_operation_timeouts_are_fixed_and_bounded(self):
        """Source policies bound potentially slow mutation commands separately from reads."""
        source = source_segment(class_node(adapter_tree(), "DeployClient"))
        self.assertIn("timeout=300", source)
        self.assertIn("timeout=120", source)

    def test_local_child_capture_is_bounded_and_closes_inherited_pipes(self):
        """Exercise only the local capture primitive, never Ludus or server behavior."""
        result = ludus._capture_process(
            (sys.executable, "-c", "import sys; sys.stdout.write('o'*8192); sys.stderr.write('e'*8192)"),
            timeout=3,
            max_output=1024,
            env={},
        )
        self.assertEqual(len(result.stdout.encode()), 1024)
        self.assertEqual(len(result.stderr.encode()), 1024)
        self.assertTrue(result.truncated)

        command = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)']); "
            "time.sleep(3)"
        )
        result = ludus._capture_process((sys.executable, "-c", command), timeout=0.2, max_output=1024, env={})
        self.assertTrue(result.timed_out)

    def test_capture_cleanup_is_bounded_and_handles_base_exception(self):
        """Static contract requires whole-process-group cleanup and bounded waits."""
        tree = adapter_tree()
        node = next((item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_capture_process"), None)
        self.assertIsNotNone(node, "process capture must be independently testable with local child processes")
        source = source_segment(node)
        self.assertIn("BaseException", source)
        self.assertIn("killpg", source)
        self.assertIn("timeout", source)
        for call in (item for item in ast.walk(node) if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == "wait"):
            self.assertTrue(any(keyword.arg == "timeout" for keyword in call.keywords), "process wait must be bounded")

    def test_secret_registry_only_collects_sensitive_values_and_rejects_cycles(self):
        """Ordinary labels cannot poison metadata filters; cyclic YAML fails closed."""
        config = {
            "a": "ordinary-value",
            "password": "pw-canary",
            "nested": {"api_key": "key-canary", "client_secret": "secret-canary"},
        }
        self.assertEqual(
            ludus._collect_sensitive_values(config),
            frozenset({"pw-canary", "key-canary", "secret-canary"}),
        )
        cyclic = {}
        cyclic["nested"] = cyclic
        with self.assertRaises(ludus.LudusAdapterError):
            ludus._collect_sensitive_values(cyclic)

    def test_history_id_validator_screens_selected_id_against_secrets(self):
        """User-selected IDs cannot bypass the same secret filter used for listed IDs."""
        self.assertIsNone(ludus._safe_history_id("run-secret-12", ("secret",)))
        self.assertEqual(ludus._safe_history_id("run-123", ("secret",)), "run-123")

    def test_only_exact_authorization_error_wrapper_is_a_definitive_denial(self):
        """Extra fields and non-string error values remain ambiguous, never failures."""
        denial = "You are not authorized to perform this ansible action"
        result = ludus._classify_upload_response({"error": denial})
        self.assertEqual(result.disposition, "failure")
        for value in (
            {"error": denial, "debug": "extra"},
            {"error": [denial]},
            ["error", denial],
        ):
            with self.subTest(value=value):
                result = ludus._classify_upload_response(value)
                self.assertEqual(result.disposition, "unknown")

    def test_bound_session_cannot_be_retargeted_by_target_reassignment(self):
        """Deployment capability must remain anchored to the discovered target."""
        node = class_node(adapter_tree(), "BoundSession")
        frozen = any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "dataclass"
            and any(keyword.arg == "frozen" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    for keyword in decorator.keywords)
            for decorator in node.decorator_list
        )
        target_property = any(
            isinstance(item, ast.FunctionDef) and item.name == "target"
            and any(isinstance(decorator, ast.Name) and decorator.id == "property" for decorator in item.decorator_list)
            for item in node.body
        )
        self.assertTrue(frozen or target_property, "BoundSession.target must be immutable")
        deploy_factory = next(node for node in adapter_tree().body if isinstance(node, ast.FunctionDef) and node.name == "enable_deploy")
        self.assertIn("session.target", source_segment(deploy_factory))

    def test_upload_error_branch_type_checks_before_message_lookup(self):
        """An arbitrary JSON top-level value cannot crash classification via .get()."""
        source = source_segment(class_node(adapter_tree(), "DeployClient"))
        self.assertIn("isinstance(value, dict)", source)
        self.assertIn("Role upload outcome is unknown", source)

    def test_unknown_range_states_are_not_accepted_as_known(self):
        """State decoding recognizes only the pinned contract's explicit state set."""
        allowed = {"DEPLOYING", "DESTROYING", "ERROR", "ABORTED", "DESTROYED", "NEVER DEPLOYED", "SUCCESS"}
        for state in allowed:
            self.assertEqual(ludus._validate_range_state(state), state)
        for state in ("", "UNKNOWN", "SUCCESS ", "success", "DESTROYING\x00"):
            with self.subTest(state=state), self.assertRaises(ludus.LudusAdapterError):
                ludus._validate_range_state(state)

    def test_sensitive_metadata_is_suppressed_not_relayed(self):
        """Secret-bearing, control-bearing, or overlong values cannot enter public metadata."""
        safe = ludus._safe_metadata_text
        self.assertIsNone(safe("token=canary-123", ("canary-123",)))
        self.assertIsNone(safe("line\nnext", ()))
        self.assertIsNone(safe("x" * 4097, ()))
        self.assertEqual(safe("SUCCESS", ("canary-123",)), "SUCCESS")

    def test_secret_registry_populates_before_config_and_upload_data_boundary(self):
        """Config and staged defaults are registered before data reaches output handling."""
        reader = source_segment(class_node(adapter_tree(), "_ReadClient"))
        deploy = source_segment(class_node(adapter_tree(), "DeployClient"))
        active = reader[reader.index("def active_config"):reader.index("def status")]
        upload = deploy[deploy.index("def upload"):deploy.index("def launch")]
        self.assertLess(active.index("_register_config_secrets"), active.index("return value"))
        self.assertLess(upload.index("_register_role_secrets"), upload.index("_execute"))


if __name__ == "__main__":
    unittest.main()
