"""Static contracts for protected Helm failure diagnostics."""

import ast
from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).parents[1]
HELM_TASKS = ROLE / "tasks" / "kubernetes" / "helm.yml"
PLUGIN = ROLE / "action_plugins" / "splunk_container_logs_helm_diagnostics.py"

HELM_ARGUMENTS = {
    "kubeconfig": "{{ splunk_container_logs_kubeconfig }}",
    "context": "{{ splunk_container_logs_kube_context }}",
    "name": "{{ splunk_container_logs_k8s_release }}",
    "release_namespace": "{{ splunk_container_logs_k8s_namespace }}",
    "chart_ref": "{{ splunk_container_logs_k8s_workspace.path }}/{{ splunk_container_logs_k8s_chart_filename }}",
    "values_files": ["{{ splunk_container_logs_k8s_workspace.path }}/values.yaml"],
    "state": "present",
    "create_namespace": False,
    "dependency_update": False,
    "update_repo_cache": False,
    "force": False,
    "replace": False,
    "skip_crds": True,
    "reset_values": True,
    "wait": True,
    "timeout": "10m0s",
}

CLASSIFICATION_KEYS = (
    "helm_command_error", "unsupported_parameter", "reset_values_rejected",
    "chart_schema_marker", "template_yaml_marker", "timeout_marker", "unknown",
)


def module(task, name):
    return task.get(name, task.get(f"ansible.builtin.{name}"))


def normalized(value):
    return " ".join(str(value).split())


def assignments(tree):
    return {
        target.id: node.value
        for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }


class HelmDiagnosticsStatic(unittest.TestCase):
    def test_original_apply_and_check_tasks_and_outer_cleanup_are_frozen(self):
        tasks = yaml.safe_load(HELM_TASKS.read_text(encoding="utf-8"))
        outer = next(task for task in tasks
                     if task.get("name") == "Stage verify render compare and converge the reviewed chart")
        names = [task.get("name") for task in outer["block"]]
        self.assertEqual(names, [
            "Create a protected local chart workspace",
            "Download only the manifest-reviewed chart bytes",
            "Render protected logs-only values",
            "Create only the owned collector namespace",
            "Create or update only the explicitly owned caller-token Secret",
            "Compare the reviewed release without mutation in check mode",
            "Diagnose protected Helm apply failure without exposing values",
        ])

        check_task = outer["block"][5]
        self.assertEqual(module(check_task, "kubernetes.core.helm"), HELM_ARGUMENTS)
        self.assertEqual(check_task.get("when"), "ansible_check_mode")
        self.assertIs(check_task.get("no_log"), True)
        wrapper = outer["block"][6]
        self.assertEqual(list(wrapper), ["name", "block", "rescue"])
        self.assertEqual(len(wrapper["block"]), 1)
        apply_task = wrapper["block"][0]
        self.assertEqual(apply_task.get("name"), "Apply only a real reviewed Helm diff with bounded wait")
        self.assertEqual(module(apply_task, "kubernetes.core.helm"), HELM_ARGUMENTS)
        self.assertEqual(apply_task.get("environment"), {"HELM_DIFF_THREE_WAY_MERGE": "true"})
        self.assertEqual(apply_task.get("when"), "not ansible_check_mode")
        self.assertIs(apply_task.get("no_log"), True)

        rescue = wrapper["rescue"]
        self.assertEqual(len(rescue), 1)
        nested = rescue[0]
        self.assertEqual(list(nested), ["name", "block", "rescue", "always"])
        action = nested["block"][0]
        self.assertEqual(action.get("action"), "splunk_container_logs_helm_diagnostics")
        self.assertEqual(action.get("args", {}), {})
        self.assertEqual(action.get("register"), "splunk_container_logs_helm_diagnostics_result")
        self.assertIs(action.get("no_log"), True)
        report = nested["block"][1]
        self.assertEqual(module(report, "debug")["msg"],
                         "{{ splunk_container_logs_helm_diagnostics_result.report }}")
        self.assertIs(report.get("no_log"), False)
        fallback = nested["rescue"][0]
        self.assertEqual(module(fallback, "debug").get("msg"),
                         "Helm failure diagnostics unavailable.")
        self.assertIs(fallback.get("no_log"), False)
        terminal = nested["always"][0]
        self.assertEqual(module(terminal, "fail").get("msg"),
                         "Protected Helm apply failed; review the sanitized diagnostics.")
        self.assertIs(terminal.get("no_log"), True)
        self.assertNotIn("no mutations", module(terminal, "fail")["msg"].lower())

        self.assertEqual(len(outer["always"]), 1)
        self.assertEqual(outer["always"][0], {
            "name": "Remove the protected local chart workspace",
            "ansible.builtin.file": {
                "path": "{{ splunk_container_logs_k8s_workspace.path | default('') }}",
                "state": "absent",
            },
            "when": "splunk_container_logs_k8s_workspace.path | default('') | length > 0",
            "check_mode": False,
            "no_log": True,
        })

    def test_classifier_parser_and_output_contract_are_static_and_allowlisted(self):
        self.assertTrue(PLUGIN.is_file())
        source = PLUGIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        tree_assignments = assignments(tree)
        self.assertEqual(ast.literal_eval(tree_assignments["CLASSIFICATION_KEYS"]),
                         CLASSIFICATION_KEYS)
        prefixes = ast.literal_eval(tree_assignments["UNSUPPORTED_PREFIXES"])
        self.assertEqual(prefixes, (
            "Unsupported parameters for (kubernetes.core.helm) module: ",
            "Unsupported parameters for (helm) module: ",
        ))
        self.assertEqual(ast.literal_eval(tree_assignments["SUPPORTED_DELIMITER"]),
                         ". Supported parameters include:")

        functions = {
            node.name: node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        unsupported_parser = functions["_parse_unsupported_parameters"]
        parser_calls = [node for node in ast.walk(unsupported_parser) if isinstance(node, ast.Call)]
        self.assertTrue(any(
            isinstance(node.func, ast.Attribute) and node.func.attr == "split"
            and node.args and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "SUPPORTED_DELIMITER"
            for node in parser_calls
        ))
        self.assertIn("re.fullmatch", ast.unparse(unsupported_parser))
        self.assertIn("reset_values", ast.unparse(functions["_classify_messages"]))
        self.assertNotIn("supported parameters include", ast.unparse(functions["_classify_messages"]).lower())
        self.assertIn("ansible_failed_result", source)
        self.assertIn("ansible_failed_task", source)
        self.assertIn("failure_context_unavailable", source)
        self.assertIn("isinstance", source)
        self.assertIn("Mapping", source)

        safe_returns = [
            node.value for node in ast.walk(functions["run"])
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
            and any(isinstance(key, ast.Constant) and key.value == "report"
                    for key in node.value.keys)
        ]
        self.assertEqual(len(safe_returns), 1)
        safe_report = next(
            value for key, value in zip(safe_returns[0].keys, safe_returns[0].values)
            if isinstance(key, ast.Constant) and key.value == "report"
        )
        self.assertEqual(
            tuple(ast.literal_eval(key) for key in safe_report.keys),
            ("failure_context", "classification", "metadata"),
        )
        empty_classification = next(
            node.value for node in ast.walk(functions["_empty_classification"])
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
        )
        self.assertEqual(tuple(ast.literal_eval(key) for key in empty_classification.keys),
                         CLASSIFICATION_KEYS)
        metadata_shape = next(
            node.value for node in ast.walk(functions["_metadata_report"])
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
        )
        self.assertEqual(tuple(ast.literal_eval(key) for key in metadata_shape.keys),
                         ("fqcn", "provenance", "collections_context", "status"))
        self.assertIn('"module_path"', source)
        self.assertIn('"module_realpath"', source)
        self.assertIn('"version"', source)
        self.assertIn('"sha256"', source)

        read_bounded = functions["_read_bounded"]
        self.assertIn("os.path.getsize(path)", ast.unparse(read_bounded))
        self.assertIn("source_file.read(maximum_bytes + 1)", ast.unparse(read_bounded))
        open_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        ]
        self.assertEqual(len(open_calls), 1)
        self.assertIn("_read_bounded(module_realpath, MAX_MODULE_BYTES)", source)
        self.assertIn("_read_bounded(manifest_realpath, MAX_MANIFEST_BYTES)", source)

        action_class = next(node for node in tree.body
                            if isinstance(node, ast.ClassDef) and node.name == "ActionModule")
        self.assertTrue(any(
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_requires_connection"
                    for target in node.targets)
            and isinstance(node.value, ast.Constant) and node.value.value is False
            for node in action_class.body
        ))
        self.assertIn("post_failure_loader_snapshot", source)
        self.assertIn("failure_context_unavailable", source)
        self.assertIn("collection_context_unavailable", source)
        self.assertIn("unexpected_identity", source)
        self.assertIn("unexpected_layout", source)
        self.assertIn("metadata_error", source)
        self.assertIn("find_plugin_with_context", source)
        self.assertIn("kubernetes.core.helm", source)
        self.assertIn("collection_list=validated_collections", source)
        self.assertIn("realpath", source)
        self.assertIn("commonpath", source)
        self.assertIn("MANIFEST.json", source)
        self.assertIn(
            "collection_root = os.path.dirname(os.path.dirname(os.path.dirname(normalized_module_path)))",
            source,
        )
        self.assertIn(
            "os.path.relpath(module_realpath, collection_root_realpath) != MODULE_RELATIVE_PATH",
            source,
        )
        self.assertIn('MODULE_RELATIVE_PATH = os.path.join("plugins", "modules", "helm.py")', source)
        self.assertIn("sha256", source)
        self.assertIn("except Exception", source)

        for forbidden in (
            "_execute_module", "run_command", "subprocess", "templar", "jinja2",
            "ansible_failed_result.*args", "traceback", "str(exc)", "repr(exc)",
            "os.environ", "sys.path", "clear_cache", "reset_values_supported",
            "runpy", "importlib", "__import__(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
