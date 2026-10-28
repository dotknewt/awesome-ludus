"""Focused static contracts for the detect-evil range configuration."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
RANGE_PATH = Path(__file__).resolve().parents[1] / "range-config.yml"


def load_yaml(path):
    return yaml.safe_load(path.read_text())


class DetectEvilRangeStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = load_yaml(RANGE_PATH)
        cls.vms = {vm["vm_name"]: vm for vm in cls.config["ludus"]}

    @staticmethod
    def role_name(assignment):
        return assignment if isinstance(assignment, str) else assignment["name"]

    def test_dependencies_resolve_to_assigned_roles_and_execution_graph_is_acyclic(self):
        edges = {}
        for vm_name, vm in self.vms.items():
            assignments = vm.get("roles", [])
            nodes = [(vm_name, self.role_name(assignment)) for assignment in assignments]
            for node in nodes:
                edges.setdefault(node, set())
            for previous, current in zip(nodes, nodes[1:]):
                edges[previous].add(current)

        for vm_name, vm in self.vms.items():
            assignments = vm.get("roles", [])
            names = [self.role_name(assignment) for assignment in assignments]
            for assignment, name in zip(assignments, names):
                for dependency in assignment.get("depends_on", []) if isinstance(assignment, dict) else []:
                    target = self.vms.get(dependency["vm_name"])
                    self.assertIsNotNone(target, f"{vm_name}/{name} references missing VM {dependency['vm_name']}")
                    target_roles = [self.role_name(item) for item in target.get("roles", [])]
                    self.assertIn(dependency["role"], target_roles,
                                  f"{vm_name}/{name} references unassigned role {dependency['role']} on {dependency['vm_name']}")
                    edges[(dependency["vm_name"], dependency["role"])].add((vm_name, name))

        visiting, visited = set(), set()

        def visit(node):
            self.assertNotIn(node, visiting, f"role dependency cycle: {node}")
            if node in visited:
                return
            visiting.add(node)
            for successor in edges[node]:
                visit(successor)
            visiting.remove(node)
            visited.add(node)

        for node in edges:
            visit(node)

    def test_new_linux_vm_installs_forwarder_before_logging_and_grants_reader(self):
        vm = self.vms["{{ range_id }}-linux"]
        assignments = vm["roles"]
        self.assertEqual([self.role_name(item) for item in assignments], ["splunk_forwarder", "linux_logging"])
        server = {"vm_name": "{{ range_id }}-splunk", "role": "linux_splunk_server"}
        self.assertEqual(assignments[0]["depends_on"], [server])
        self.assertEqual(assignments[1]["depends_on"], [
            {"vm_name": "{{ range_id }}-linux", "role": "splunk_forwarder"}
        ])
        self.assertEqual(vm["role_vars"]["ludus_linux_logging_read_users"], ["splunkfwd"])

    def test_runner_order_and_dependencies_are_preserved(self):
        runner = self.vms["{{ range_id }}-runner"]
        self.assertEqual([self.role_name(item) for item in runner["roles"]], [
            "splunk_forwarder", "linux_gitlab_runner", "linux_k3s_bootstrap", "linux_logging", "splunk_container_logs"
        ])
        by_role = {self.role_name(item): item for item in runner["roles"] if isinstance(item, dict)}
        self.assertEqual(by_role["splunk_forwarder"]["depends_on"], [
            {"vm_name": "{{ range_id }}-splunk", "role": "linux_splunk_server"}
        ])
        self.assertEqual(by_role["linux_gitlab_runner"]["depends_on"], [
            {"vm_name": "{{ range_id }}-gitlab", "role": "linux_gitlab_ce"}
        ])
        self.assertEqual(by_role["linux_logging"]["depends_on"], [
            {"vm_name": "{{ range_id }}-runner", "role": "splunk_forwarder"},
            {"vm_name": "{{ range_id }}-runner", "role": "linux_k3s_bootstrap"},
        ])
        self.assertEqual(by_role["splunk_container_logs"]["depends_on"], [
            {"vm_name": "{{ range_id }}-splunk", "role": "linux_splunk_server"},
            {"vm_name": "{{ range_id }}-runner", "role": "linux_k3s_bootstrap"},
        ])

    def test_shared_windows_inputs_and_linux_monitors_match_forwarder_contract(self):
        global_vars = self.config["global_role_vars"]
        defaults = load_yaml(ROOT / "ansible/roles/splunk_forwarder/defaults/main.yml")
        self.assertEqual(global_vars["splunk_forwarder_inputs"], [
            {"name": "WinEventLog://Security"}, {"name": "WinEventLog://System"},
            {"name": "WinEventLog://Application"},
            {"name": "WinEventLog://Microsoft-Windows-Sysmon/Operational"},
            {"name": "WinEventLog://Microsoft-Windows-PowerShell/Operational"},
        ])
        self.assertEqual(self.vms["{{ range_id }}-dc"]["roles"][-1], "splunk_forwarder")
        self.assertEqual(self.vms["{{ range_id }}-adcs"]["roles"][1], "splunk_forwarder")
        self.assertEqual(self.vms["{{ range_id }}-win11"]["roles"][-1], "splunk_forwarder")
        self.assertEqual(global_vars["splunk_forwarder_monitors"], defaults["splunk_forwarder_monitors"])

    def test_gpo_link_shapes_use_valid_target_and_boolean_flags(self):
        links = self.vms["{{ range_id }}-dc"]["role_vars"]["windows_logging_policy_links"]
        self.assertEqual(set(links), {"logging", "enrollment", "defender"})
        for entries in links.values():
            self.assertIsInstance(entries, list)
            self.assertTrue(entries)
            for entry in entries:
                self.assertIsInstance(entry.get("target"), str)
                self.assertTrue(entry["target"])
                self.assertIsInstance(entry.get("enabled"), bool)
                self.assertIsInstance(entry.get("enforced"), bool)
                if "order" in entry:
                    self.assertIs(type(entry["order"]), int)
                    self.assertGreater(entry["order"], 0)

    def test_container_collection_remains_kubernetes_and_docker_executor_is_unchanged(self):
        runner = self.vms["{{ range_id }}-runner"]
        vars_ = runner["role_vars"]
        self.assertEqual(vars_["splunk_container_logs_mode"], "kubernetes")
        self.assertEqual(vars_["splunk_container_logs_k8s_log_paths"], ["/var/log/pods"])
        self.assertIs(vars_["ludus_gitlab_runner_smoke_ci_enabled"], False)
        runner_role = ROOT / "ansible/roles/linux_gitlab_runner"
        defaults = load_yaml(runner_role / "defaults/main.yml")
        registration = (runner_role / "tasks/register.yml").read_text()
        self.assertEqual(defaults["ludus_gitlab_runner_executor_image"], "alpine:latest")
        self.assertIn("- --executor\n      - docker\n      - --docker-image", registration)


if __name__ == "__main__":
    unittest.main()
