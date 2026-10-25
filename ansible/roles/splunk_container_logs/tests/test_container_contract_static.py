from pathlib import Path
import base64, importlib.util, sys, unittest
import yaml
KUBERNETES_TASK_FILES = (
    "tasks/kubernetes/input.yml", "tasks/kubernetes/cluster-state.yml",
    "tasks/kubernetes/secret.yml", "tasks/kubernetes/helm.yml",
)
REQUIRED = {
    "defaults/main.yml", "vars/artifacts.yml", "meta/main.yml", "LICENSE", "README.md",
    "tasks/main.yml", "tasks/preflight.yml", "tasks/docker.yml", "tasks/kubernetes.yml", "handlers/main.yml",
    *KUBERNETES_TASK_FILES,
    "templates/docker-otel.yaml.j2", "templates/kubernetes-values.yaml.j2",
    "templates/splunk-container-logs.service.j2", "filter_plugins/container_paths.py",
    "filter_plugins/kubernetes_contract.py",
}
DEFAULTS = {
    "splunk_container_logs_mode": "",
    "splunk_container_logs_owner_id": "ludus-container-logs",
    "splunk_container_logs_hec_endpoint": "",
    "splunk_container_logs_hec_index": "",
    "splunk_container_logs_hec_token": "",
    "splunk_container_logs_tls_verify": True,
    "splunk_container_logs_allow_insecure_http": False,
    "splunk_container_logs_ca_file": "",
    "splunk_container_logs_start_at": "end",
    "splunk_container_logs_docker_include": [],
    "splunk_container_logs_docker_exclude": [],
    "splunk_container_logs_docker_state_dir": "/var/lib/splunk-container-logs",
    "splunk_container_logs_collector_url": "https://github.com/signalfx/splunk-otel-collector/releases/download/v0.163.0/splunk-otel-collector_0.163.0_amd64.tar.gz",
    "splunk_container_logs_kubeconfig": "", "splunk_container_logs_kube_context": "",
    "splunk_container_logs_k8s_cluster_name": "", "splunk_container_logs_k8s_namespace": "splunk-logs",
    "splunk_container_logs_k8s_release": "splunk-container-logs", "splunk_container_logs_k8s_existing_secret": "",
    "splunk_container_logs_k8s_node_selector": {}, "splunk_container_logs_k8s_tolerations": [],
    "splunk_container_logs_k8s_log_paths": ["/var/log/pods"],
    "splunk_container_logs_k8s_checkpoint_path": "/var/addon/splunk/otel_pos",
    "splunk_container_logs_k8s_queue_path": "/var/addon/splunk/exporter_queue",
    "splunk_container_logs_chart_url": "https://github.com/signalfx/splunk-otel-collector-chart/releases/download/splunk-otel-collector-0.163.0/splunk-otel-collector-0.163.0.tgz",
    "splunk_container_logs_queue_size": 1000, "splunk_container_logs_queue_max_disk_mib": 512,
}
def logical_name(path):
    value = path.as_posix().rstrip("/")
    return next((name for name in REQUIRED if value == name or value.endswith(f"/{name}")), None)
class Artifacts:
    def __init__(self, arguments):
        self.paths, self.errors = {}, []
        for argument in arguments:
            name = logical_name(Path(argument))
            if name is None:
                self.errors.append(f"unrecognized explicit artifact path: {argument}")
            elif name in self.paths:
                self.errors.append(f"duplicate explicit artifact path: {name}")
            else:
                self.paths[name] = Path(argument)
    def read(self, case, name):
        case.assertFalse(self.errors, "Malformed harness input: " + "; ".join(self.errors))
        case.assertIn(name, self.paths, f"Missing explicit input path: {name}")
        case.assertTrue(self.paths[name].is_file(), f"Missing container-role artifact: {name}")
        try:
            return self.paths[name].read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            case.fail(f"Unable to read UTF-8 artifact {name}: {exc}")
    def yaml(self, case, name, expected_type):
        try:
            value = yaml.safe_load(self.read(case, name))
        except yaml.YAMLError as exc: case.fail(f"Malformed YAML in {name}: {exc}")
        case.assertIsInstance(value, expected_type, f"Malformed {name}")
        return value
ARTIFACTS = Artifacts(sys.argv[1:])
sys.argv[1:] = []
def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))
def is_module_task(task):
    return any(key.startswith(("ansible.builtin.", "kubernetes.core.")) for key in task)
def task_text(tasks): return yaml.safe_dump(tasks, sort_keys=True)
def walk_tasks(tasks):
    """Yield Ansible tasks in source execution order, including nested blocks."""
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            if isinstance(task.get(section, []), list):
                yield from walk_tasks(task.get(section, []))
def kubernetes_tasks(case):
    return [task for name in KUBERNETES_TASK_FILES for task in ARTIFACTS.yaml(case, name, list)]
def load_kubernetes_helper(case):
    path = ARTIFACTS.paths["filter_plugins/kubernetes_contract.py"]
    spec = importlib.util.spec_from_file_location("kubernetes_contract", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper
class ContainerContractStatic(unittest.TestCase):
    def test_required_explicit_artifacts_exist(self):
        for name in sorted(REQUIRED):
            ARTIFACTS.read(self, name)
    def test_public_defaults_are_typed_and_overrideable(self):
        defaults = ARTIFACTS.yaml(self, "defaults/main.yml", dict)
        for name, expected in DEFAULTS.items():
            self.assertIn(name, defaults)
            self.assertIs(type(defaults[name]), type(expected), f"wrong type for {name}")
            self.assertEqual(defaults[name], expected, f"wrong default for {name}")
    def test_internal_manifest_freezes_script_free_collector_identity(self):
        manifest = ARTIFACTS.yaml(self, "vars/artifacts.yml", dict)["splunk_container_logs_artifacts"]
        collector = manifest["collector"]
        self.assertEqual(collector["version"], "0.163.0")
        self.assertEqual(collector["artifact_type"], "script-free release tar archive")
        self.assertEqual(collector["sha256"],
                         "sha256:bb44c773423c88392c7e27d309c43bfae937ce1b3b0b81831dbc07149a28ca49")
        install = collector["install_contract"]
        self.assertEqual(install["selected_entry"], "./splunk-otel-collector/bin/otelcol")
        self.assertEqual(install["selected_entry_normalized"], "splunk-otel-collector/bin/otelcol")
        self.assertEqual(install["entry_sha256"],
                         "sha256:bfd3de154091ff3449e7d9a346b8ad1f7795dcb0ce5bd366e10d1f704fc3cb4f")
        self.assertEqual(manifest["queue"]["size"], 1000)
        self.assertEqual(manifest["queue"]["max_disk_mib"], 512)
    def test_internal_manifest_freezes_reviewed_chart_and_linux_amd64_image(self):
        manifest = ARTIFACTS.yaml(self, "vars/artifacts.yml", dict)["splunk_container_logs_artifacts"]
        chart, image = manifest["chart"], manifest["chart"]["images"]["collector"]
        self.assertEqual(chart["version"], "0.163.0")
        self.assertEqual(chart["sha256"], "sha256:8f7a64a2c10583932c82dcb2f761c2daef748d4b29fb7440092df144a4b0f9d9")
        self.assertEqual(image["platform"], "linux/amd64")
        self.assertEqual(image["digest"], "sha256:e9f0b6afea725b5b6e2a516db64399d37437c09cbe1dac6a5ab0697d8f93a668")
        self.assertIn("mirror whose bytes match", manifest["v1_input_policy"]["chart_release"])
    def test_metadata_and_license_are_owned(self):
        meta = ARTIFACTS.yaml(self, "meta/main.yml", dict)
        self.assertEqual(meta.get("galaxy_info", {}).get("role_name"), "splunk_container_logs")
        self.assertEqual(meta.get("galaxy_info", {}).get("author"), "dotknewt")
        self.assertTrue(ARTIFACTS.read(self, "LICENSE").strip())
    def test_entrypoint_preflights_then_dispatches_exactly_one_selected_mode(self):
        tasks = ARTIFACTS.yaml(self, "tasks/main.yml", list)
        text = task_text(tasks)
        self.assertIn("artifacts.yml", text)
        preflight = [i for i, task in enumerate(tasks)
                     if module(task, "include_tasks") == "preflight.yml"]
        docker = [i for i, task in enumerate(tasks)
                   if module(task, "include_tasks") == "docker.yml"]
        kubernetes = [i for i, task in enumerate(tasks)
                      if module(task, "include_tasks") == "kubernetes.yml"]
        self.assertEqual((len(preflight), len(docker), len(kubernetes)), (1, 1, 1))
        self.assertLess(preflight[0], min(docker[0], kubernetes[0]))
        self.assertIn("splunk_container_logs_mode == 'docker'", str(tasks[docker[0]].get("when")))
        self.assertIn("splunk_container_logs_mode == 'kubernetes'", str(tasks[kubernetes[0]].get("when")))
        mode_tasks = ARTIFACTS.yaml(self, "tasks/kubernetes.yml", list)
        expected_includes = [name.removeprefix("tasks/") for name in KUBERNETES_TASK_FILES]
        self.assertEqual([module(task, "include_tasks") for task in mode_tasks],
                         expected_includes)
    def test_preflight_requires_one_supported_mode_and_explicit_transport(self):
        text = task_text(ARTIFACTS.yaml(self, "tasks/preflight.yml", list))
        for token in ("splunk_container_logs_mode is string", "docker", "kubernetes", "splunk_container_logs_hec_endpoint",
                      "splunk_container_logs_hec_index", "splunk_container_logs_hec_token",
                      "splunk_container_logs_allow_insecure_http", "splunk_container_logs_tls_verify",
                      "splunk_container_logs_ca_file", "splunk_container_logs_start_at"):
            self.assertIn(token, text)
        self.assertRegex(text, r"https://|startswith\('https://'")
        self.assertRegex(text, r"http://|startswith\('http://'")
    def test_docker_preflight_covers_sources_format_readability_and_ownership(self):
        text = task_text(ARTIFACTS.yaml(self, "tasks/docker.yml", list))
        for token in ("docker_include", "docker_exclude", "json-file", "realpath", "readable",
                       "owner_id", "ludus-container-logs", "state_dir", "duplicate", "amd64",
                       "Debian", "Ubuntu", "systemd", "nearest", "symlink", "UnitPath", "LoadState", "FragmentPath",
                       "DropInPaths", "Names", "Transient", "splunk-container-.service.d",
                       "splunk-.service.d", "service.d", "resolved_service_aliases", "same-name", "entry_sha256", "stdout", "stderr", "[0-9]{4}"):
            self.assertIn(token, text, f"missing Docker guard token {token}")
        tasks = list(walk_tasks(ARTIFACTS.yaml(self, "tasks/docker.yml", list)))
        provenance = next(i for i, task in enumerate(tasks) if "DropInPaths" in task_text(task))
        first_write = next(i for i, task in enumerate(tasks) if any(module(task, name) is not None for name in ("file", "get_url", "unarchive", "template", "copy", "systemd_service")))
        self.assertLess(provenance, first_write, "systemd provenance must be checked before writes")
        helper = ARTIFACTS.read(self, "filter_plugins/container_paths.py")
        for token in ("normalize_path", "path_ancestors", "paths_overlap", "sandbox_accessible", "docker_envelope_valid"):
            self.assertIn(token, helper)
        self.assertNotIn("subprocess", helper)
    def test_secret_bearing_tasks_are_redacted(self):
        groups = [ARTIFACTS.yaml(self, name, list) for name in ("tasks/preflight.yml", "tasks/docker.yml")]
        groups.append(kubernetes_tasks(self))
        for tasks in groups:
            tasks = walk_tasks(tasks)
            exposed = [task.get("name", "unnamed") for task in tasks
                       if is_module_task(task)
                       and any(token in task_text(task) for token in
                               ("splunk_container_logs_hec_token",
                                "splunk_container_logs_k8s_token_b64",
                                "splunk_container_logs_k8s_ca_b64"))
                       and task.get("no_log") is not True]
            self.assertFalse(exposed, f"token-bearing tasks without no_log: {exposed}")
    def test_kubernetes_defaults_and_preflight_are_explicit_and_fail_closed(self):
        defaults = ARTIFACTS.yaml(self, "defaults/main.yml", dict)
        self.assertIn("splunk_container_logs_k8s_log_paths", defaults,
                      "missing Kubernetes log-path default")
        self.assertEqual(defaults["splunk_container_logs_k8s_log_paths"], ["/var/log/pods"])
        text = task_text(kubernetes_tasks(self))
        for token in ("kubeconfig", "kube_context", "k8s_cluster_name", "k8s_node_selector",
                      "k8s_existing_secret", "splunk_container_logs_hec_token", "exclusive",
                      "kubernetes.core.k8s_info", "kubernetes.core.helm_info", "pending", "failed",
                      "owner_id", "managed", "context", "namespace"):
            self.assertIn(token, text, f"missing Kubernetes preflight contract {token}")
        self.assertRegex(text, r"k8s_node_selector[^\n]*(length|bool)|k8s_node_selector\s*\|\s*length")
    def test_existing_secret_is_read_only_and_strictly_validated(self):
        tasks = list(walk_tasks(kubernetes_tasks(self)))
        text = task_text(tasks) + ARTIFACTS.read(self, "filter_plugins/kubernetes_contract.py")
        for token in ("splunk_platform_hec_token", "splunk_platform_hec_ca_file",
                      "b64decode", "validate=True", "load_verify_locations", "cadata"):
            self.assertIn(token, text)
        secret_reads = [task for task in tasks if is_module_task(task)
                        and "splunk_platform_hec_token" in task_text(task)]
        self.assertTrue(secret_reads)
        self.assertTrue(all(task.get("no_log") is True for task in secret_reads))
        secret_writes = [task for task in tasks if task.get("kubernetes.core.k8s", {}).get("state") == "present"
                         and task.get("kubernetes.core.k8s", {}).get("definition", {}).get("kind") == "Secret"]
        self.assertTrue(secret_writes, "caller-token mode must create an explicitly owned Secret")
        for task in secret_writes:
            self.assertIn("owner_id", task_text(task))
            self.assertRegex(str(task.get("when", "")), r"k8s_existing_secret.*(length\s*==\s*0|==\s*'')")
    def test_kubernetes_values_are_logs_only_and_close_network_listeners(self):
        source = ARTIFACTS.read(self, "templates/kubernetes-values.yaml.j2")
        for snippet in ("logsEnabled: true", "metricsEnabled: false", "tracesEnabled: false",
                        "service:\n    enabled: false", "hostNetwork: false", "skipInitContainers: true",
                        "validateSecret: false", "kubernetes.io/arch: amd64"):
            self.assertIn(snippet, source)
        self.assertIn("kubernetes.io/os: linux", source)
        for section in ("clusterReceiver", "gateway", "operator", "obi", "targetallocator", "journald",
                        "logsToMetrics", "remoteManagement", "instrumentation", "discovery"):
            self.assertRegex(source, rf"(?s){section}:.*?enabled:\s*false")
        self.assertRegex(source, r"(?s)operatorcrds:.*?install:\s*false")
        for port in ("otlp", "otlp-http", "zipkin", "jaeger-thrift", "jaeger-grpc", "opampforwarder"):
            self.assertRegex(source, rf"(?m)^\s*{port}:\s*(null|~)\s*$")
        self.assertNotIn("hostPort:", source)
    def test_kubernetes_values_preserve_readonly_logs_and_both_persistence_overrides(self):
        source = ARTIFACTS.read(self, "templates/kubernetes-values.yaml.j2")
        for token in ("splunk_container_logs_k8s_log_paths", "readOnly: true",
                      "splunk_container_logs_k8s_checkpoint_path", "splunk_container_logs_k8s_queue_path",
                      "persistentQueue:", "storagePath:", "file_storage/persistent_queue:",
                      "splunk_hec/platform_logs:", "storage: file_storage/persistent_queue",
                      "max_size:", "fsync: true", "block_on_overflow: true", "receivers: [file_log]"):
            self.assertIn(token, source)
    def test_kubernetes_secret_mapping_and_transport_are_chart_native(self):
        source = ARTIFACTS.read(self, "templates/kubernetes-values.yaml.j2")
        for token in ("secret:", "create: false", "splunk_container_logs_k8s_secret_name",
                      "splunkPlatform:", "caFile:", "insecureSkipVerify:"):
            self.assertIn(token, source)
        tasks = list(walk_tasks(kubernetes_tasks(self)))
        producers = [task for task in tasks if isinstance(module(task, "set_fact"), dict)
                     and "splunk_container_logs_k8s_secret_name" in module(task, "set_fact")]
        self.assertEqual(len(producers), 1)
        for token in ("splunk_container_logs_k8s_existing_secret",
                      "splunk_container_logs_k8s_release", "-hec"):
            self.assertIn(token, task_text(producers[0]))
        self.assertIn("clusterName: {{ splunk_container_logs_k8s_cluster_name", source)
    def test_selector_grammar_and_linux_amd64_are_enforced_before_cluster_state(self):
        helper = load_kubernetes_helper(self)
        valid = (("example.com/pool", "workers_1"), ("kubernetes.io/os", "linux"))
        invalid = (("Bad Prefix/key", "x"), ("example.com/", "x"), ("bad-/key", "x"),
                   (("a" * 254) + "/key", "x"), ("x" * 64, "x"),
                   ("key", "x" * 64), ("key", "_bad"))
        self.assertTrue(all(helper.kubernetes_label_pair_valid(*pair) for pair in valid))
        self.assertTrue(all(not helper.kubernetes_label_pair_valid(*pair) for pair in invalid))
        input_text = task_text(ARTIFACTS.yaml(self, "tasks/kubernetes/input.yml", list))
        for token in ("splunk_k8s_label_pair_valid", "kubernetes.io/os", "linux",
                      "kubernetes.io/arch", "amd64"):
            self.assertIn(token, input_text)
        tasks = list(walk_tasks(kubernetes_tasks(self)))
        selector_guard = next(i for i, task in enumerate(tasks)
                              if "splunk_k8s_label_pair_valid" in task_text(task))
        first_cluster_write = next(i for i, task in enumerate(tasks)
                                   if task.get("kubernetes.core.k8s", {}).get("state") == "present")
        self.assertLess(selector_guard, first_cluster_write)
    def test_persistent_paths_and_chart_source_identity_are_bounded(self):
        helper = load_kubernetes_helper(self)
        self.assertTrue(helper.kubernetes_persistent_paths_valid(
            ["/var/addon/splunk/otel_pos", "/var/addon/splunk/exporter_queue"]))
        for paths in (["/var/addon/splunk/.", "/var/addon/splunk/queue"],
                      ["/var/addon/splunk/state/..", "/var/addon/splunk/queue"],
                      ["/var/addon/splunk/state/", "/var/addon/splunk/queue"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/state"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/state/queue"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/queue # marker"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/queue name"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/queue\nnext"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/queue:tag"],
                      ["/var/addon/splunk/state", "/var/addon/splunk/queue[0]"]):
            self.assertFalse(helper.kubernetes_persistent_paths_valid(paths))
        input_source = ARTIFACTS.read(self, "tasks/kubernetes/input.yml")
        self.assertIn("'/var/log/pods' in splunk_container_logs_k8s_log_paths", input_source)
        self.assertIn("splunk_k8s_persistent_paths_valid", input_source)
        values = ARTIFACTS.read(self, "templates/kubernetes-values.yaml.j2")
        state = ARTIFACTS.read(self, "tasks/kubernetes/cluster-state.yml")
        self.assertIn("ludus.splunk/log-paths", values)
        self.assertIn("ludus.splunk/log-paths", state)
    def test_observed_daemonset_host_paths_use_normalized_overlap_semantics(self):
        helper = load_kubernetes_helper(self)
        disjoint = helper.kubernetes_host_paths_disjoint
        selected = ["/var/log/pods"]
        for observed in (["/var/log"], ["/var/log/pods/workload"],
                         ["/var/log/pods"], ["/var/log/../log/pods"],
                         ["/var//log/pods/"], ["/"]):
            self.assertFalse(disjoint(observed, selected))
        self.assertFalse(disjoint(["/var/log/pods"], ["/var/log"]))
        self.assertFalse(disjoint(["/var/log/pods"], ["/"]))
        for observed in (["/var/log/containers"], ["/var/log/pods-old"], []):
            self.assertTrue(disjoint(observed, selected))
        for unsupported in (["var/log/pods"], [None], ["/var/log/\x00pods"]):
            self.assertFalse(disjoint(unsupported, selected))
        self.assertFalse(disjoint(["/var/log/pods"], []))
        state = ARTIFACTS.read(self, "tasks/kubernetes/cluster-state.yml")
        self.assertIn("splunk_k8s_host_paths_disjoint", state)
        self.assertNotIn("intersect(splunk_container_logs_k8s_log_paths)", state)
    def test_cluster_discovery_and_consumers_are_redacted(self):
        tasks = list(walk_tasks(ARTIFACTS.yaml(self, "tasks/kubernetes/cluster-state.yml", list)))
        discovery = [task for task in tasks if "kubernetes.core.k8s_cluster_info" in task]
        self.assertEqual(len(discovery), 1)
        self.assertIs(discovery[0].get("no_log"), True)
        consumers = [task for task in tasks if is_module_task(task)
                     and "splunk_container_logs_cluster_info" in task_text(task)]
        self.assertTrue(consumers)
        self.assertTrue(all(task.get("no_log") is True for task in consumers))
    def test_check_mode_rejects_absent_namespace_or_release(self):
        tasks = ARTIFACTS.yaml(self, "tasks/kubernetes/secret.yml", list)
        guards = [task for task in tasks if "ansible_check_mode" in str(task.get("when", ""))]
        self.assertEqual(len(guards), 1)
        text = task_text(guards[0])
        self.assertIn("namespace_info.resources", text)
        self.assertIn("release_info.status is defined", text)
        self.assertIn("fresh-install", text)
        self.assertIs(guards[0].get("no_log"), True)
    def test_credential_digest_changes_without_exposing_plaintext(self):
        helper = load_kubernetes_helper(self)
        first = helper.kubernetes_credential_contract(base64.b64encode(b"token-one").decode())
        second = helper.kubernetes_credential_contract(base64.b64encode(b"token-two").decode())
        self.assertNotEqual(first["digest"], second["digest"])
        self.assertNotIn("token", first["digest"])
        with self.assertRaises((ValueError, TypeError)):
            helper.kubernetes_credential_contract("not base64!")
        source = ARTIFACTS.read(self, "templates/kubernetes-values.yaml.j2")
        self.assertIn("ludus.splunk/credential-digest", source)
        self.assertIn("splunk_container_logs_k8s_credential_digest", source)
        self.assertNotIn("splunk_container_logs_hec_token", source)
    def test_runtime_pins_and_cluster_identity_come_from_manifest(self):
        source = ARTIFACTS.read(self, "templates/kubernetes-values.yaml.j2")
        tasks = task_text(kubernetes_tasks(self))
        for token in ("artifacts.chart.version", "artifacts.tooling.helm.version",
                      "artifacts.tooling.helm_diff.version", "artifacts.chart.sha256"):
            self.assertIn(token, tasks)
        self.assertIn("artifacts.chart.required_logs_only_values.image.otelcol", source)
        for duplicated in ("0.163.0", "3.20.0", "3.15.15",
                           "e9f0b6afea725b5b6e2a516db64399d37437c09cbe1dac6a5ab0697d8f93a668"):
            self.assertNotIn(duplicated, tasks + source)
        cluster_state = ARTIFACTS.read(self, "tasks/kubernetes/cluster-state.yml")
        self.assertIn("release_values.get('clusterName'", cluster_state)
    def test_kubernetes_chart_and_values_lifecycle_is_protected_and_check_safe(self):
        tasks = list(walk_tasks(kubernetes_tasks(self)))
        text = task_text(tasks)
        for token in ("splunk_container_logs_chart_url", "chart.sha256", "validate_certs", "0600",
                      "HELM_DIFF_THREE_WAY_MERGE", "kubernetes.core.helm", "wait", "timeout",
                      "force: false", "replace: false", "always"):
            self.assertIn(token, text)
        mutating = [task for task in tasks if (task.get("kubernetes.core.k8s", {}).get("state") == "present"
                    or "kubernetes.core.helm" in task) and "kubernetes.core.helm_info" not in task]
        self.assertTrue(mutating)
        self.assertTrue(all("ansible_check_mode" in str(task.get("when", "")) for task in mutating))
        cluster_deletes = [task.get("name", "unnamed") for task in tasks
                           if task.get("kubernetes.core.k8s", {}).get("state") == "absent"
                           or task.get("kubernetes.core.helm", {}).get("state") == "absent"]
        self.assertFalse(cluster_deletes, f"cluster deletion/uninstall is forbidden: {cluster_deletes}")
        for forbidden in ("helm uninstall", "force: true", "replace: true"):
            self.assertNotIn(forbidden, text)
    def test_install_is_reviewed_executable_not_package_or_script(self):
        tasks = list(walk_tasks(ARTIFACTS.yaml(self, "tasks/docker.yml", list)))
        text = task_text(tasks)
        self.assertIn("selected_entry", text)
        self.assertIn("sha256", text)
        self.assertIn("splunk_container_logs_collector_url", text)
        self.assertNotIn("--strip-components", text)
        for name in ("apt", "package", "dnf", "yum", "script", "shell"):
            self.assertFalse(any(module(task, name) is not None for task in tasks), name)
    def test_collector_template_is_filelog_only_and_parses_docker_envelope(self):
        source = ARTIFACTS.read(self, "templates/docker-otel.yaml.j2")
        for token in ("filelog/docker_json", "splunk_hec/logs", "service:", "pipelines:",
                      "logs:", "com.splunk.source", "sourcetype: docker:json"):
            self.assertIn(token, source)
        self.assertRegex(source, r"(?s)type:\s*json_parser.*?parse_from:\s*body.*?parse_to:\s*attributes")
        self.assertRegex(source, r"(?s)type:\s*time_parser.*?parse_from:\s*attributes\.time")
        self.assertRegex(source, r"(?s)from:\s*attributes\.log.*?to:\s*body")
        for forbidden in ("metrics:", "traces:", "otlp:", "docker_stats"):
            self.assertNotIn(forbidden, source)
    def test_template_wires_transport_offsets_and_bounded_queue(self):
        source = ARTIFACTS.read(self, "templates/docker-otel.yaml.j2")
        for token in ("splunk_container_logs_hec_endpoint", "splunk_container_logs_hec_index",
                      "splunk_container_logs_hec_token", "splunk_container_logs_tls_verify",
                      "splunk_container_logs_ca_file", "splunk_container_logs_start_at",
                      "file_storage/checkpoints", "file_storage/exporter_queue", "storage:",
                      "sending_queue", "splunk_container_logs_queue_size",
                      "splunk_container_logs_queue_max_disk_mib", "block_on_overflow", "retry_on_failure"):
            self.assertIn(token, source)
    def test_systemd_unit_sandboxes_and_mounts_sources_read_only(self):
        source = ARTIFACTS.read(self, "templates/splunk-container-logs.service.j2")
        for token in ("ProtectSystem=strict", "NoNewPrivileges=true", "PrivateTmp=true",
                      "ReadOnlyPaths=", "splunk_container_logs_resolved_includes", "ReadWritePaths=",
                      "splunk_container_logs_docker_state_dir", "collector.yaml"):
            self.assertIn(token, source)
        self.assertNotIn("docker.sock", source)
    def test_candidate_validation_precedes_active_config_and_restart(self):
        tasks = list(walk_tasks(ARTIFACTS.yaml(self, "tasks/docker.yml", list)))
        candidate = next(i for i, task in enumerate(tasks) if "candidate" in task_text(task).lower()
                         and module(task, "template") is not None)
        validation = next(i for i, task in enumerate(tasks) if i > candidate
                          and "validate" in task_text(task).lower() and module(task, "command") is not None)
        replacement = next(i for i, task in enumerate(tasks) if i > validation
                           and "collector.yaml" in task_text(task) and module(task, "copy") is not None)
        self.assertLess(candidate, validation)
        self.assertLess(validation, replacement)
        self.assertIn("splunk_container_logs_restart", str(tasks[replacement].get("notify", "")))
        self.assertNotEqual(tasks[validation].get("failed_when"), False)
    def test_handler_restarts_only_owned_service(self):
        handlers = ARTIFACTS.yaml(self, "handlers/main.yml", list)
        owned = [task for task in handlers
                 if "splunk_container_logs_restart" in str(task.get("listen", ""))]
        self.assertEqual(len(owned), 1)
        service = module(owned[0], "systemd_service") or module(owned[0], "systemd")
        self.assertEqual(service.get("name"), "splunk-container-logs")
        self.assertEqual(service.get("state"), "restarted")
    def test_sources_and_runtime_are_never_mutated(self):
        source = "\n".join(ARTIFACTS.read(self, name) for name in
                            ("tasks/main.yml", "tasks/preflight.yml", "tasks/docker.yml",
                             "tasks/kubernetes.yml", *KUBERNETES_TASK_FILES,
                             "handlers/main.yml", "templates/kubernetes-values.yaml.j2",
                             "templates/splunk-container-logs.service.j2"))
        for forbidden in ("/var/run/docker.sock", "/run/docker.sock", "daemon.json", "docker.service",
                          "systemctl restart docker", "chmod", "chown", "docker group", "minikube",
                          "kubeadm", "audit-policy", "test pod"):
            self.assertNotIn(forbidden, source.lower())
if __name__ == "__main__": unittest.main()
