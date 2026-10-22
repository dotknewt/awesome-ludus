from pathlib import Path
import sys, unittest
import yaml
REQUIRED = {
    "defaults/main.yml", "vars/artifacts.yml", "meta/main.yml", "LICENSE", "README.md",
    "tasks/main.yml", "tasks/preflight.yml", "tasks/docker.yml", "handlers/main.yml", "templates/docker-otel.yaml.j2",
    "templates/splunk-container-logs.service.j2", "filter_plugins/container_paths.py",
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
        case.assertTrue(self.paths[name].is_file(), f"Missing C3 artifact: {name}")
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
def task_text(tasks): return yaml.safe_dump(tasks, sort_keys=True)
def walk_tasks(tasks):
    """Yield Ansible tasks in source execution order, including nested blocks."""
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            if isinstance(task.get(section, []), list):
                yield from walk_tasks(task.get(section, []))
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
    def test_metadata_and_license_are_owned(self):
        meta = ARTIFACTS.yaml(self, "meta/main.yml", dict)
        self.assertEqual(meta.get("galaxy_info", {}).get("role_name"), "splunk_container_logs")
        self.assertEqual(meta.get("galaxy_info", {}).get("author"), "dotknewt")
        self.assertTrue(ARTIFACTS.read(self, "LICENSE").strip())
    def test_entrypoint_loads_manifest_preflights_then_dispatches_docker_only(self):
        tasks = ARTIFACTS.yaml(self, "tasks/main.yml", list)
        text = task_text(tasks)
        self.assertIn("artifacts.yml", text)
        preflight = [i for i, task in enumerate(tasks)
                     if module(task, "include_tasks") == "preflight.yml"]
        docker = [i for i, task in enumerate(tasks)
                  if module(task, "include_tasks") == "docker.yml"]
        self.assertEqual((len(preflight), len(docker)), (1, 1))
        self.assertLess(preflight[0], docker[0])
        self.assertIn("splunk_container_logs_mode == 'docker'", str(tasks[docker[0]].get("when")))
        self.assertNotIn("kubernetes.yml", text, "C3 must not dispatch Kubernetes")
    def test_preflight_requires_one_docker_mode_and_explicit_transport(self):
        text = task_text(ARTIFACTS.yaml(self, "tasks/preflight.yml", list))
        for token in ("type_debug", "docker", "kubernetes", "C3", "splunk_container_logs_hec_endpoint",
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
        for name in ("tasks/preflight.yml", "tasks/docker.yml"):
            tasks = walk_tasks(ARTIFACTS.yaml(self, name, list))
            exposed = [task.get("name", "unnamed") for task in tasks
                       if "splunk_container_logs_hec_token" in task_text(task)
                       and task.get("no_log") is not True]
            self.assertFalse(exposed, f"token-bearing tasks without no_log: {exposed}")
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
                            "handlers/main.yml", "templates/splunk-container-logs.service.j2"))
        for forbidden in ("/var/run/docker.sock", "/run/docker.sock", "daemon.json", "docker.service",
                          "systemctl restart docker", "chmod", "chown", "docker group"):
            self.assertNotIn(forbidden, source.lower())
if __name__ == "__main__": unittest.main()
