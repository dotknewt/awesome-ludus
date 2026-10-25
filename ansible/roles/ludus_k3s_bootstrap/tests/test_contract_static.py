"""Pure source contracts for the pinned native K3s bootstrap role.

These tests parse only explicitly supplied files. They do not execute Ansible,
download artifacts, start services, or establish runtime compatibility.
"""

from pathlib import Path
import ast
import re
import sys
import unittest

import yaml


REQUIRED = {
    "defaults/main.yml",
    "vars/artifacts.yml",
    "meta/main.yml",
    "tasks/main.yml",
    "tasks/preflight.yml",
    "tasks/artifacts.yml",
    "tasks/python.yml",
    "tasks/service.yml",
    "tasks/tool-integrity.yml",
    "tasks/verify.yml",
    "handlers/main.yml",
    "templates/k3s.service.j2",
    "files/kubernetes-requirements.txt",
    "files/verify_python_lock.py",
    "README.md",
    "LICENSE",
}

LOCKED_PACKAGES = {
    "aiohappyeyeballs", "aiohttp", "aiohttp-retry", "aiosignal",
    "annotated-types", "attrs", "certifi", "charset-normalizer",
    "durationpy", "frozenlist", "idna", "jsonpatch", "jsonpointer",
    "kubernetes", "multidict", "oauthlib", "propcache", "pydantic",
    "pydantic-core", "python-dateutil", "pyyaml", "requests",
    "requests-oauthlib", "six", "typing-extensions", "typing-inspection",
    "urllib3", "websocket-client", "yarl",
}


def logical_name(path):
    value = path.as_posix().rstrip("/")
    return next(
        (name for name in REQUIRED if value == name or value.endswith(f"/{name}")),
        None,
    )


class Artifacts:
    def __init__(self, arguments):
        self.paths = {}
        self.errors = []
        for argument in arguments:
            path = Path(argument)
            name = logical_name(path)
            if name is None:
                self.errors.append(f"unrecognized explicit artifact path: {argument}")
            elif name in self.paths:
                self.errors.append(f"duplicate explicit artifact path: {name}")
            else:
                self.paths[name] = path

    def read(self, case, name):
        case.assertFalse(self.errors, "Malformed harness input: " + "; ".join(self.errors))
        case.assertIn(name, self.paths, f"Missing explicit input path: {name}")
        path = self.paths[name]
        case.assertTrue(path.is_file(), f"Missing required role artifact: {name} ({path})")
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            case.fail(f"Unable to read UTF-8 artifact {name}: {exc}")

    def yaml(self, case, name, expected_type):
        try:
            value = yaml.safe_load(self.read(case, name))
        except yaml.YAMLError as exc:
            case.fail(f"Malformed YAML in {name}: {exc}")
        case.assertIsInstance(value, expected_type, f"Malformed {name}")
        return value


ARTIFACTS = Artifacts(sys.argv[1:])
sys.argv[1:] = []


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


class K3sBootstrapContractStatic(unittest.TestCase):
    def test_required_explicit_artifacts_exist(self):
        for name in sorted(REQUIRED):
            ARTIFACTS.read(self, name)

    def test_metadata_and_platform_are_exact(self):
        metadata = ARTIFACTS.yaml(self, "meta/main.yml", dict)["galaxy_info"]
        self.assertEqual(metadata["role_name"], "ludus_k3s_bootstrap")
        self.assertEqual(metadata["author"], "dotknewt")
        self.assertEqual(metadata["platforms"], [{"name": "Ubuntu", "versions": ["noble"]}])

        preflight = ARTIFACTS.read(self, "tasks/preflight.yml")
        for contract in (
            "ansible_distribution == 'Ubuntu'",
            "ansible_distribution_version is version('24.04', '>=')",
            "ansible_distribution_version is version('25.04', '<')",
            "ansible_architecture == 'x86_64'",
            "ansible_service_mgr == 'systemd'",
        ):
            self.assertIn(contract, preflight)

    def test_release_urls_versions_digests_and_paths_are_frozen(self):
        pins = ARTIFACTS.yaml(self, "vars/artifacts.yml", dict)
        expected = {
            "ludus_k3s_bootstrap_k3s_version": "v1.37.1+k3s1",
            "ludus_k3s_bootstrap_k3s_sha256": "92b94582eb7b34a8cf532e6006842b9ed215a6783cf56a3dd6271fd35243b2c0",
            "ludus_k3s_bootstrap_helm_version": "3.20.0",
            "ludus_k3s_bootstrap_helm_sha256": "dbb4c8fc8e19d159d1a63dda8db655f9ffa4aac1b9a6b188b34a40957119b286",
            "ludus_k3s_bootstrap_helm_diff_version": "3.15.15",
            "ludus_k3s_bootstrap_helm_diff_sha256": "504e99410611daa70702362e1b10dc74929df8a912cb3f6b5d21d1ee9d0cb7d9",
            "ludus_k3s_bootstrap_kubeconfig": "/etc/rancher/k3s/k3s.yaml",
            "ludus_k3s_bootstrap_kube_context": "default",
            "ludus_k3s_bootstrap_cluster_name": "default",
            "ludus_k3s_bootstrap_kube_user": "default",
            "ludus_k3s_bootstrap_api_server": "https://127.0.0.1:6443",
            "ludus_k3s_bootstrap_python": "/opt/ludus-k3s/python/bin/python",
        }
        for name, value in expected.items():
            self.assertEqual(pins[name], value)
        self.assertEqual(
            pins["ludus_k3s_bootstrap_k3s_url"],
            "https://github.com/k3s-io/k3s/releases/download/v1.37.1%2Bk3s1/k3s",
        )
        self.assertEqual(pins["ludus_k3s_bootstrap_helm_url"],
                         "https://get.helm.sh/helm-v3.20.0-linux-amd64.tar.gz")
        self.assertEqual(
            pins["ludus_k3s_bootstrap_helm_diff_url"],
            "https://github.com/databus23/helm-diff/releases/download/"
            "v3.15.15/helm-diff-linux-amd64.tgz",
        )

    def test_kubeconfig_contract_matches_native_k3s_admin_config(self):
        pins = ARTIFACTS.yaml(self, "vars/artifacts.yml", dict)
        preflight = ARTIFACTS.yaml(self, "tasks/preflight.yml", list)
        verify = ARTIFACTS.yaml(self, "tasks/verify.yml", list)
        identity = {
            "ludus_k3s_bootstrap_cluster_name": "default",
            "ludus_k3s_bootstrap_kube_context": "default",
            "ludus_k3s_bootstrap_kube_user": "default",
            "ludus_k3s_bootstrap_api_server": "https://127.0.0.1:6443",
        }
        for variable, value in identity.items():
            self.assertEqual(pins.get(variable), value)
        self.assertEqual(set(identity.values()), {"default", "https://127.0.0.1:6443"})
        checks = (
            (preflight, "Require exact existing kubeconfig names when present", "(ludus_k3s_bootstrap_existing_kubeconfig.stdout | from_json)"),
            (verify, "Require exact kubeconfig names", "ludus_k3s_bootstrap_kubeconfig_data"),
        )
        for tasks, name, data in checks:
            task = next(task for task in tasks if task.get("name") == name)
            assertions = module(task, "assert")["that"]
            source = " ".join(str(assertion) for assertion in assertions)
            for value in identity:
                self.assertIn(value, source)
            for shape in (
                ".clusters | map(attribute='name') | list == [", ".contexts | map(attribute='name') | list == [",
                ".users | map(attribute='name') | list == [", "['current-context'] ==",
                ".contexts[0].context.cluster ==", ".contexts[0].context.user ==",
                ".clusters[0].cluster.server ==",
            ):
                self.assertIn(shape, source)
            user = f"{data}.users[0].user"
            for auth_field in ("token", "password", "exec", "auth-provider"):
                self.assertIn(f"'{auth_field}' not in {user}", source)
            for embedded in ("certificate-authority-data", "client-certificate-data", "client-key-data"):
                self.assertIn(f"['{embedded}'] is defined", source)
                self.assertIn(f"['{embedded}'] | length > 0", source)

    def test_every_direct_download_is_checksum_verified_and_no_script_runs(self):
        tasks = ARTIFACTS.yaml(self, "tasks/artifacts.yml", list)
        downloads = [module(task, "get_url") for task in tasks if module(task, "get_url")]
        self.assertEqual(len(downloads), 3)
        for download in downloads:
            self.assertTrue(str(download["url"]).startswith("{{ ludus_k3s_bootstrap_"))
            self.assertRegex(str(download["checksum"]), r"^sha256:\{\{ .+_sha256 \}\}$")

        source = "\n".join(
            ARTIFACTS.read(self, name)
            for name in ("tasks/artifacts.yml", "tasks/python.yml", "tasks/service.yml")
        )
        for forbidden in (
            "ansible.builtin.shell", "ansible.builtin.script", "curl ", "wget ",
            "helm plugin install", "get-helm-3", "get.k3s.io",
        ):
            self.assertNotIn(forbidden, source)

    def test_existing_state_is_protected_before_writes_and_no_uninstall_exists(self):
        main = ARTIFACTS.yaml(self, "tasks/main.yml", list)
        includes = [module(task, "include_tasks") for task in main if module(task, "include_tasks")]
        self.assertEqual(includes[0], "preflight.yml")
        self.assertIn("artifacts.yml", includes[1])

        preflight = ARTIFACTS.read(self, "tasks/preflight.yml")
        for destination in (
            "ludus_k3s_bootstrap_k3s_binary", "ludus_k3s_bootstrap_unit_path",
            "ludus_k3s_bootstrap_config_dir", "ludus_k3s_bootstrap_data_dir",
            "ludus_k3s_bootstrap_helm_binary", "ludus_k3s_bootstrap_root_helm_plugins",
            "ludus_k3s_bootstrap_python_root", "ludus_k3s_bootstrap_owner_marker",
        ):
            self.assertIn(destination, preflight)
        self.assertIn("Refuse unowned K3s destinations", preflight)
        self.assertIn("refusing replacement or adoption", preflight)
        for contract in (
            "Inventory the exact K3s configuration directory",
            "ludus_k3s_bootstrap_config_entries.stdout_lines == ['k3s.yaml']",
            "EnvironmentFiles",
            "Environment=",
            "expected_modes",
            "ludus_k3s_bootstrap_helm_archive",
            "ludus_k3s_bootstrap_helm_diff_archive",
            "ludus_k3s_bootstrap_requirements",
            "tool-integrity.yml",
        ):
            self.assertIn(contract, preflight)

        role_source = "\n".join(
            ARTIFACTS.read(self, name)
            for name in REQUIRED if name.startswith("tasks/") or name == "handlers/main.yml"
        ).lower()
        for forbidden in ("k3s-uninstall", "cluster-reset", "state: absent", "helm uninstall"):
            self.assertNotIn(forbidden, role_source)

    def test_service_uses_embedded_containerd_and_does_not_manage_docker(self):
        unit = ARTIFACTS.read(self, "templates/k3s.service.j2")
        self.assertIn("ExecStart={{ ludus_k3s_bootstrap_k3s_binary }} server", unit)
        self.assertIn("--write-kubeconfig-mode=0600", unit)
        self.assertNotIn("--docker", unit)
        self.assertNotIn("container-runtime-endpoint", unit)
        self.assertNotIn("TimeoutStartSec=0", unit)
        self.assertRegex(unit, r"(?m)^TimeoutStartSec=[1-9][0-9]*s$")

        service = ARTIFACTS.read(self, "tasks/service.yml")
        handlers = ARTIFACTS.read(self, "handlers/main.yml")
        self.assertIn("no_block: true", service)
        self.assertIn("no_block: true", handlers)

        install_tasks = ARTIFACTS.yaml(self, "tasks/artifacts.yml", list)
        apt_names = next(module(task, "apt")["name"] for task in install_tasks if module(task, "apt"))
        self.assertEqual(apt_names, ["ca-certificates", "python3-venv"])
        self.assertFalse({"docker.io", "containerd", "containerd.io"} & set(apt_names))

    def test_helm_diff_uses_root_reported_directory_and_direct_archive_extraction(self):
        source = ARTIFACTS.read(self, "tasks/artifacts.yml")
        for contract in (
            "      - env\n      - HELM_PLUGINS",
            "ludus_k3s_bootstrap_helm_plugins_dir.stdout",
            "Extract the verified helm-diff archive without running hooks",
            "Install helm-diff directly from the verified archive layout",
            "/helm-diff/diff/",
            "HOME: /root",
        ):
            self.assertIn(contract, source)
        self.assertNotIn("plugin\n      - install", source)

        integrity = ARTIFACTS.read(self, "tasks/tool-integrity.yml")
        for contract in (
            "linux-amd64/helm", "diff/bin/diff", "diff/plugin.yaml", "tarfile.open",
            "ludus_k3s_bootstrap_helm_sha256",
            "ludus_k3s_bootstrap_helm_diff_sha256",
            ".member_sha256 ==", ".destination_sha256",
        ):
            self.assertIn(contract, integrity)

    def test_python_lock_is_complete_hashed_and_installed_only_in_the_venv(self):
        lock = ARTIFACTS.read(self, "files/kubernetes-requirements.txt")
        requirement_lines = [line for line in lock.splitlines() if line and not line.startswith("#")]
        packages = set()
        for line in requirement_lines:
            match = re.fullmatch(
                r"([A-Za-z0-9-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})", line
            )
            self.assertIsNotNone(match, f"not an exact one-hash lock entry: {line}")
            packages.add(match.group(1).lower())
        self.assertEqual(packages, LOCKED_PACKAGES)
        for direct in ("kubernetes==37.0.1", "PyYAML==6.0.3", "jsonpatch==1.36"):
            self.assertIn(direct, lock)

        python_tasks = ARTIFACTS.read(self, "tasks/python.yml")
        for contract in (
            "--system-site-packages", "--require-hashes", "--only-binary=:all:",
            "--ignore-installed", "ludus_k3s_bootstrap_python", "      - pip\n      - check",
        ):
            self.assertIn(contract, python_tasks)
        self.assertNotIn("ansible.builtin.pip", python_tasks)
        verifier = ARTIFACTS.read(self, "files/verify_python_lock.py")
        for contract in (
            "importlib.metadata", "sysconfig.get_path", "missing",
            "mismatched", "unexpected", "pip", "setuptools",
        ):
            self.assertIn(contract, verifier)
        for contract in (
            "verify_python_lock.py", "missing | length == 0",
            "mismatched | length == 0", "unexpected | length == 0",
            "'pip' in ludus_k3s_bootstrap_python_lock_result.bootstrap",
        ):
            self.assertIn(contract, python_tasks)

    def test_readiness_requires_api_names_one_schedulable_node_and_exact_tools(self):
        verify = ARTIFACTS.read(self, "tasks/verify.yml")
        for contract in (
            "--raw=/readyz", "stdout == 'ok'",
            "[ludus_k3s_bootstrap_cluster_name]", "[ludus_k3s_bootstrap_kube_context]",
            "node_list | length == 1", "kubernetes.io/os", "kubernetes.io/arch",
            "spec.unschedulable", "NoSchedule", "NoExecute", "Ready",
            "['37.0.1', '6.0.3', '1.36']",
        ):
            self.assertIn(contract, verify)

        tasks = ARTIFACTS.yaml(self, "tasks/verify.yml", list)
        exact_versions = next(
            task for task in tasks if task.get("name") == "Require exact tool and Python versions"
        )
        assertions = module(exact_versions, "assert")["that"]

        def runtime_pattern(output_name):
            expression = next(value for value in assertions if output_name in value)
            encoded = expression.split("('", 1)[1].rsplit("')", 1)[0]
            return ast.literal_eval("'" + encoded + "'")

        k3s_pattern = runtime_pattern("k3s_version_output.stdout")
        helm_pattern = runtime_pattern("helm_version_output.stdout")
        plugin_pattern = runtime_pattern("plugin_output.stdout")
        self.assertIsNotNone(re.search(k3s_pattern, "k3s version v1.37.1+k3s1 (abc123)"))
        self.assertIsNone(re.search(k3s_pattern, "k3s version v1x37x1+k3s1 (abc123)"))
        self.assertIsNotNone(re.search(helm_pattern, "v3.20.0+gabc123"))
        self.assertIsNone(re.search(helm_pattern, "v3x20x0+gabc123"))
        self.assertIsNotNone(re.search(plugin_pattern, "NAME VERSION DESCRIPTION\ndiff 3.15.15 Preview"))
        self.assertIsNone(re.search(plugin_pattern, "diff 3x15x15 Preview"))

        for task in tasks:
            command = module(task, "command")
            if not command:
                continue
            argv = [str(value) for value in command.get("argv", [])]
            if "kubectl" in argv:
                self.assertIn("--request-timeout=10s", argv)
                self.assertFalse({"apply", "create", "delete", "run"} & set(argv))

        node_read = next(task for task in tasks if task.get("name") == "Wait for the exact single-node runtime contract")
        node_until = str(node_read.get("until", ""))
        self.assertEqual(node_read["retries"], "{{ ludus_k3s_bootstrap_api_retries }}")
        for contract in (
            "kubernetes.io/os", "kubernetes.io/arch", "unschedulable",
            "NoSchedule", "NoExecute", "Ready", "containerRuntimeVersion",
            "containerd://",
        ):
            self.assertIn(contract, node_until)

        self.assertIn("containerRuntimeVersion", verify)
        self.assertIn("containerd://", verify)
        self.assertIn("Inspect the generated kubeconfig metadata", verify)
        self.assertNotIn("Protect the generated root kubeconfig", verify)

    def test_output_facts_and_interpreter_switch_are_exact(self):
        tasks = ARTIFACTS.yaml(self, "tasks/main.yml", list)
        outputs = module(tasks[-1], "set_fact")
        self.assertEqual(outputs, {
            "ludus_k3s_kubeconfig_path": "{{ ludus_k3s_bootstrap_kubeconfig }}",
            "ludus_k3s_kube_context": "{{ ludus_k3s_bootstrap_kube_context }}",
            "ludus_k3s_cluster_name": "{{ ludus_k3s_bootstrap_cluster_name }}",
            "ludus_k3s_python_interpreter": "{{ ludus_k3s_bootstrap_python }}",
            "ansible_python_interpreter": "{{ ludus_k3s_bootstrap_python }}",
        })

    def test_readme_documents_fail_closed_non_uninstall_and_runtime_limits(self):
        readme = ARTIFACTS.read(self, "README.md")
        for contract in (
            "fail closed", "no reset, uninstall, migration, adoption, or cleanup",
            "creates no pod", "remain unverified",
            "Existing Docker and distro containerd state is not a collision",
        ):
            self.assertIn(contract, readme)


if __name__ == "__main__":
    unittest.main()
