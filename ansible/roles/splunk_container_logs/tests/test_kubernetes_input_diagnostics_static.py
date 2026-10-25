"""Static source contracts for value-free Kubernetes input diagnostics."""

import ast
from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).parents[1]
INPUT_TASKS = ROLE / "tasks" / "kubernetes" / "input.yml"
PLUGIN = ROLE / "action_plugins" / "splunk_container_logs_input_diagnostics.py"

KUBERNETES_ASSERTIONS = (
    "splunk_container_logs_kubeconfig is string",
    "splunk_container_logs_kubeconfig | length > 0",
    "splunk_container_logs_kube_context is string",
    "splunk_container_logs_kube_context | length > 0",
    "splunk_container_logs_k8s_cluster_name is string",
    "splunk_container_logs_k8s_cluster_name | length > 0",
    "splunk_container_logs_k8s_namespace is match('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",
    "splunk_container_logs_k8s_release is match('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",
    "splunk_container_logs_k8s_existing_secret is string",
    "splunk_container_logs_k8s_existing_secret | length == 0 or splunk_container_logs_k8s_existing_secret is match('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",
    "splunk_container_logs_k8s_existing_secret | length == 0 or splunk_container_logs_hec_token | length == 0",
    "splunk_container_logs_k8s_existing_secret | length == 0 or splunk_container_logs_ca_file | length == 0",
    "splunk_container_logs_k8s_node_selector is mapping",
    "splunk_container_logs_k8s_node_selector | length > 0",
    "splunk_container_logs_k8s_node_selector.get('kubernetes.io/os', 'linux') == 'linux'",
    "splunk_container_logs_k8s_node_selector.get('kubernetes.io/arch', 'amd64') == 'amd64'",
    "splunk_container_logs_k8s_tolerations is sequence",
    "splunk_container_logs_k8s_tolerations is not string",
    "splunk_container_logs_k8s_log_paths is sequence",
    "splunk_container_logs_k8s_log_paths is not string",
    "splunk_container_logs_k8s_log_paths | length > 0",
    "splunk_container_logs_k8s_log_paths | unique | length == splunk_container_logs_k8s_log_paths | length",
    "'/var/log/pods' in splunk_container_logs_k8s_log_paths",
    "splunk_container_logs_k8s_log_paths | difference(['/var/log/pods', '/var/log/containers']) | length == 0",
    "[splunk_container_logs_k8s_checkpoint_path, splunk_container_logs_k8s_queue_path] | splunk_k8s_persistent_paths_valid",
    "splunk_container_logs_chart_url is string",
    "splunk_container_logs_chart_url.startswith('https://')",
)

KUBERNETES_CONDITION_NAMES = (
    "kubeconfig_string", "kubeconfig_nonempty", "kube_context_string",
    "kube_context_nonempty", "cluster_name_string", "cluster_name_nonempty",
    "namespace_dns_label", "release_dns_label", "existing_secret_string",
    "existing_secret_empty_or_name", "secret_excludes_token", "secret_excludes_ca_file",
    "node_selector_mapping", "node_selector_nonempty", "node_selector_os_linux",
    "node_selector_arch_amd64", "tolerations_sequence", "tolerations_not_string",
    "log_paths_sequence", "log_paths_not_string", "log_paths_nonempty",
    "log_paths_unique", "log_paths_include_pods", "log_paths_supported_roots",
    "persistent_paths_valid", "chart_url_string", "chart_url_https",
)

KUBERNETES_TYPE_VARIABLES = (
    "splunk_container_logs_kubeconfig", "splunk_container_logs_kube_context",
    "splunk_container_logs_k8s_cluster_name", "splunk_container_logs_k8s_namespace",
    "splunk_container_logs_k8s_release", "splunk_container_logs_k8s_existing_secret",
    "splunk_container_logs_hec_token", "splunk_container_logs_ca_file",
    "splunk_container_logs_k8s_node_selector", "splunk_container_logs_k8s_tolerations",
    "splunk_container_logs_k8s_log_paths", "splunk_container_logs_k8s_checkpoint_path",
    "splunk_container_logs_k8s_queue_path", "splunk_container_logs_chart_url",
)


def normalized(value):
    return " ".join(str(value).split())


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


class KubernetesInputDiagnosticsStatic(unittest.TestCase):
    def test_only_string_family_checks_change_and_kubernetes_wrapper_is_fail_closed(self):
        preflight = yaml.safe_load((ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8"))
        mode_assertion = module(preflight[0], "assert")["that"]
        self.assertEqual(tuple(map(normalized, mode_assertion)), (
            "splunk_container_logs_mode is string",
            "splunk_container_logs_mode in ['docker', 'kubernetes']",
        ))
        tasks = yaml.safe_load(INPUT_TASKS.read_text(encoding="utf-8"))
        wrapper = next(task for task in tasks
                       if task.get("name") == "Validate the bounded Kubernetes input contract")
        inner = next(task for task in wrapper.get("block", [])
                     if task.get("name") == "Validate the bounded Kubernetes input contract")
        predicates = tuple(map(normalized, module(inner, "assert")["that"]))
        self.assertEqual(predicates, KUBERNETES_ASSERTIONS)
        self.assertEqual(module(inner, "assert")["fail_msg"], (
            "Kubernetes mode requires an explicit existing kubeconfig/context/cluster, "
            "mutually exclusive token authorities, a valid positive Linux/amd64 node "
            "selector, reviewed pod-log roots, distinct persistent paths, and the "
            "reviewed HTTPS chart or same-byte mirror."
        ))
        self.assertIs(inner.get("no_log"), True)
        self.assertNotIn("always", wrapper)

        rescue = wrapper["rescue"]
        self.assertEqual(len(rescue), 1)
        diagnostic = rescue[0]
        self.assertEqual(list(diagnostic), ["name", "block", "rescue", "always"])
        action = diagnostic["block"][0]
        self.assertEqual(action.get("action"), "splunk_container_logs_input_diagnostics")
        self.assertEqual(action.get("args"), {"contract": "kubernetes"})
        self.assertEqual(action.get("register"), "splunk_container_logs_kubernetes_input_diagnostics_result")
        self.assertIs(action.get("no_log"), True)
        report = diagnostic["block"][1]
        self.assertEqual(module(report, "debug")["msg"],
                         "{{ splunk_container_logs_kubernetes_input_diagnostics_result.report }}")
        self.assertIs(report.get("no_log"), False)
        fallback = diagnostic["rescue"][0]
        self.assertEqual(module(fallback, "debug").get("msg"),
                         "Input diagnostics unavailable (evaluation_error).")
        self.assertIs(fallback.get("no_log"), False)
        final_failure = diagnostic["always"][0]
        self.assertEqual(module(final_failure, "fail").get("msg"),
                         "Kubernetes input validation failed; no role changes were made.")
        self.assertIs(final_failure.get("no_log"), True)
        self.assertNotIn("when", final_failure)

    def test_fixed_selector_catalogue_and_safe_type_inputs_match_contract(self):
        source = PLUGIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        assignments = {
            target.id: node.value
            for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name)
        }
        catalogue = ast.literal_eval(assignments["KUBERNETES_CONDITION_CATALOGUE"])
        self.assertEqual(tuple(name for name, _ in catalogue), KUBERNETES_CONDITION_NAMES)
        self.assertEqual(tuple(map(normalized, (expression for _, expression in catalogue))),
                         KUBERNETES_ASSERTIONS)
        self.assertEqual(ast.literal_eval(assignments["KUBERNETES_TYPE_VARIABLES"]),
                         KUBERNETES_TYPE_VARIABLES)

        self.assertIn('args == {"contract": "kubernetes"}', source)
        self.assertIn("all_vars=task_vars", source)
        self.assertIn("KUBERNETES_CONDITION_CATALOGUE", source)
        self.assertIn("KUBERNETES_TYPE_VARIABLES", source)
        self.assertNotIn("splunk_container_logs_kubeconfig_data", source)
        self.assertNotIn("ansible_failed_result", source)
        self.assertNotIn("original_reached", source)
        self.assertNotIn("set_fact", source)


if __name__ == "__main__":
    unittest.main()
