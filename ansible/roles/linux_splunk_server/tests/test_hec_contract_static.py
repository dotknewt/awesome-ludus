"""Static source contracts for explicitly supplied C2 HEC artifacts.

These checks parse YAML and inspect structure. They do not prove Splunk
precedence, check-mode safety, failure ordering, restart behavior, or HEC
acceptance on a running server.
"""

from pathlib import Path
import ast
import sys
import unittest

import yaml


REQUIRED = {
    "defaults/main.yml", "tasks/main.yml", "handlers/main.yml", "README.md",
    "tasks/hec.yml", "tasks/hec-preflight.yml", "tasks/hec-validate.yml",
    "templates/hec-inputs.conf.j2", "templates/hec-indexes.conf.j2",
    "filter_plugins/hec_config.py",
}

EXPECTED_DEFAULTS = {
    "splunk_server_hec_enabled": False,
    "splunk_server_hec_validate": False,
    "splunk_server_hec_app": "ludus_hec",
    "splunk_server_hec_port": 8088,
    "splunk_server_hec_ssl_enabled": True,
    "splunk_server_hec_server_cert": "",
    "splunk_server_hec_token_name": "ludus-container-logs",
    "splunk_server_hec_token": "",
    "splunk_server_hec_indexes": [],
    "splunk_server_hec_default_index": "",
    "splunk_server_hec_validation_endpoint": "",
    "splunk_server_hec_validate_certs": True,
    "splunk_server_hec_ca_path": "",
}


def logical_name(path):
    value = path.as_posix().rstrip("/")
    return next((name for name in REQUIRED
                 if value == name or value.endswith(f"/{name}")), None)


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
        case.assertTrue(path.is_file(), f"Missing required C2 feature artifact: {name} ({path})")
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            case.fail(f"Unable to read UTF-8 artifact {name}: {exc}")

    def yaml(self, case, name, expected_type):
        try:
            value = yaml.safe_load(self.read(case, name))
        except yaml.YAMLError as exc:
            case.fail(f"Malformed YAML in {name}: {exc}")
        case.assertIsInstance(value, expected_type, f"Malformed {name}: expected {expected_type.__name__}")
        return value


ARTIFACTS = Artifacts(sys.argv[1:])
sys.argv[1:] = []


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


def task_text(task):
    return yaml.safe_dump(task, sort_keys=True)


class HecContractStatic(unittest.TestCase):
    def test_required_explicit_artifacts_exist(self):
        for name in sorted(REQUIRED):
            ARTIFACTS.read(self, name)

    def test_defaults_are_exact_and_strictly_typed(self):
        defaults = ARTIFACTS.yaml(self, "defaults/main.yml", dict)
        for name, expected in EXPECTED_DEFAULTS.items():
            self.assertIn(name, defaults, f"missing HEC default {name}")
            self.assertIs(type(defaults[name]), type(expected), f"wrong type for {name}")
            self.assertEqual(defaults[name], expected, f"wrong default for {name}")

    def test_entrypoint_uses_isolated_hec_include(self):
        tasks = ARTIFACTS.yaml(self, "tasks/main.yml", list)
        includes = [module(task, "include_tasks") or module(task, "import_tasks") for task in tasks]
        self.assertIn("hec.yml", includes, "server entrypoint must include isolated tasks/hec.yml")
        hec = ARTIFACTS.yaml(self, "tasks/hec.yml", list)
        hec_includes = [module(task, "include_tasks") or module(task, "import_tasks") for task in hec]
        self.assertIn("hec-preflight.yml", hec_includes)
        self.assertIn("hec-validate.yml", hec_includes)

    def test_preflight_covers_enablement_secret_index_and_tls_inputs(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec-preflight.yml", list)
        assertions = "\n".join(task_text(task) for task in tasks if module(task, "assert") is not None)
        required = (
            "splunk_server_hec_enabled", "splunk_server_hec_validate",
            "splunk_server_hec_token", "splunk_server_hec_indexes",
            "splunk_server_hec_default_index", "splunk_server_hec_port",
            "splunk_server_hec_ssl_enabled", "splunk_server_hec_server_cert",
            "splunk_server_hec_validation_endpoint", "splunk_server_hec_validate_certs",
            "splunk_server_hec_ca_path",
        )
        for variable in required:
            self.assertIn(variable, assertions, f"preflight assertion missing {variable}")
        self.assertRegex(assertions, r"hec_validate.*hec_enabled|hec_enabled.*hec_validate",
                         "validation must structurally require HEC enablement")

    def test_bounded_helper_exposes_raw_btool_and_contract_filters(self):
        source = ARTIFACTS.read(self, "filter_plugins/hec_config.py")
        functions = {node.name for node in ast.walk(ast.parse(source))
                     if isinstance(node, ast.FunctionDef)}
        required = {
            "parse_raw_files", "parse_btool", "raw_conflicts",
            "preflight_effective_conflicts", "effective_conflicts", "_require",
            "non_hec_listener_conflicts", "_effective_port",
        }
        self.assertTrue(required <= functions, f"missing bounded parser functions: {required - functions}")
        self.assertNotIn("subprocess", source, "parser helper must not execute services or commands")

    def test_preflight_parses_all_raw_stanzas_and_consumes_btool_outputs(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec-preflight.yml", list)
        source = "\n".join(task_text(task) for task in tasks)
        for fragment in (
            "splunk_hec_parse_raw_files", "splunk_hec_raw_conflicts",
            "splunk_server_hec_token", "splunk_hec_parse_btool",
            "splunk_server_hec_pre_inputs.stdout", "splunk_server_hec_pre_indexes.stdout",
            "splunk_hec_preflight_effective_conflicts",
        ):
            self.assertIn(fragment, source, f"preflight does not consume {fragment}")
        sensitive = [task for task in tasks if "splunk_hec_raw_conflicts" in task_text(task)]
        self.assertTrue(sensitive)
        self.assertTrue(all(task.get("no_log") is True for task in sensitive))

    def test_preflight_redacts_sensitive_btool_and_rejects_known_listener_collisions(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec-preflight.yml", list)
        source = "\n".join(task_text(task) for task in tasks)
        parser_source = ARTIFACTS.read(self, "filter_plugins/hec_config.py")
        for fragment in (
            "splunk_hec_non_hec_listener_conflicts",
            "splunk_server_hec_pre_inputs_parse",
            "splunk_server_hec_pre_server_parse",
            "splunk_server_hec_pre_web_parse",
            "splunk_receiver_port",
            "splunk_server_mgmt_port",
            "splunk_server_web_port",
        ):
            self.assertIn(fragment, source, f"listener preflight does not consume {fragment}")

        secret_results = ("splunk_server_hec_clustering", "splunk_server_hec_management_tls")
        for result in secret_results:
            consumers = [task for task in tasks if result in task_text(task)]
            self.assertTrue(consumers, f"missing discovery or consumer for {result}")
            self.assertTrue(all(task.get("no_log") is True for task in consumers),
                            f"{result} discovery and consumers must be redacted")

        listener_tasks = [task for task in tasks
                          if "splunk_server_hec_listener_conflicts" in task_text(task)]
        self.assertGreaterEqual(len(listener_tasks), 2)
        self.assertTrue(all(task.get("no_log") is True for task in listener_tasks))
        for stanza_prefix in ("splunktcp://", "splunktcp-ssl://",
                              "splunktcp:", "splunktcp-ssl:"):
            self.assertIn(f'"{stanza_prefix}"', parser_source)
        self.assertRegex(
            parser_source,
            r'_effective_port\(web_records,\s*"settings",\s*"mgmtHostPort"',
            "management port must come from effective web.conf [settings] provenance",
        )
        self.assertRegex(
            parser_source,
            r'_effective_boolean\(\s*server_records,\s*"httpServer",\s*"disableDefaultPort"',
            "management disablement must come from server.conf [httpServer] provenance",
        )

    def test_secret_files_and_directories_have_restricted_modes(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec.yml", list)
        writers = [task for task in tasks if module(task, "template") is not None]
        for source in ("hec-inputs.conf.j2", "hec-indexes.conf.j2"):
            matches = [task for task in writers if module(task, "template").get("src") == source]
            self.assertTrue(matches, f"missing template writer for {source}")
            self.assertTrue(all(str(module(task, "template").get("mode")) == "0600" for task in matches))
            self.assertTrue(all(task.get("no_log") is True for task in matches),
                            f"template writer for {source} must use no_log")
        active = [task for task in tasks if module(task, "copy") is not None
                  and module(task, "copy").get("remote_src") is True]
        self.assertEqual(len(active), 2, "both active files must come from protected candidates")
        self.assertTrue(all(str(module(task, "copy").get("mode")) == "0600" for task in active))
        self.assertTrue(all(task.get("no_log") is True for task in active))
        directories = [module(task, "file") for task in tasks if module(task, "file") is not None
                       and module(task, "file").get("state") == "directory"]
        self.assertTrue(directories, "owned app directories must be explicit")
        self.assertTrue(all(str(item.get("mode")) == "0700" for item in directories))

    def test_templates_express_listener_token_and_index_contract(self):
        inputs = ARTIFACTS.read(self, "templates/hec-inputs.conf.j2")
        indexes = ARTIFACTS.read(self, "templates/hec-indexes.conf.j2")
        for fragment in ("[http]", "splunk_server_hec_port", "splunk_server_hec_ssl_enabled",
                         "splunk_server_hec_token_name", "splunk_server_hec_token",
                         "splunk_server_hec_default_index", "splunk_server_hec_indexes"):
            self.assertIn(fragment, inputs)
        for fragment in ("splunk_server_hec_indexes", "homePath", "coldPath", "thawedPath"):
            self.assertIn(fragment, indexes)

    def test_restart_notification_follows_fatal_effective_check(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec.yml", list)
        checks = [index for index, task in enumerate(tasks)
                  if "btool" in task_text(task) and "--debug" in task_text(task)]
        notifiers = [index for index, task in enumerate(tasks)
                     if "splunk_server_hec_restart" in str(task.get("notify", ""))]
        self.assertTrue(checks, "missing post-write effective btool --debug check")
        self.assertTrue(notifiers, "missing HEC restart notification")
        self.assertLess(max(checks), min(notifiers), "restart notification must follow effective checks")
        for index in checks:
            self.assertNotEqual(tasks[index].get("failed_when"), False)
            self.assertFalse(tasks[index].get("ignore_errors", False))

    def test_effective_checks_use_structured_stanza_value_source_correlation(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec.yml", list)
        source = "\n".join(task_text(task) for task in tasks)
        self.assertIn("splunk_hec_parse_btool", source)
        self.assertIn("splunk_hec_effective_conflicts", source)
        self.assertIn("splunk_server_hec_effective_inputs_parse", source)
        self.assertIn("splunk_server_hec_effective_indexes_parse", source)
        self.assertIn("splunk_server_hec_effective_conflicts | length == 0", source)

    def test_pending_intent_precedes_active_replacement_and_survives_readiness(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec.yml", list)
        pending = next(index for index, task in enumerate(tasks)
                       if task.get("name") == "Persist pending restart intent before active HEC replacement")
        replacements = [index for index, task in enumerate(tasks)
                        if str(task.get("name", "")).startswith("Replace active HEC")]
        readiness = [index for index, task in enumerate(tasks)
                     if module(task, "wait_for") is not None or "process readiness" in task.get("name", "")]
        clear = next(index for index, task in enumerate(tasks)
                     if task.get("name") == "Clear resolved HEC pending restart marker")
        self.assertEqual(len(replacements), 2)
        self.assertLess(pending, min(replacements))
        self.assertLess(max(readiness), clear)
        self.assertEqual(str(module(tasks[pending], "copy").get("mode")), "0600")
        self.assertTrue(tasks[pending].get("no_log"))

    def test_hec_file_mutations_are_excluded_from_check_mode(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec.yml", list)
        mutations = [task for task in tasks
                     if any(module(task, name) is not None for name in ("file", "copy", "template"))]
        self.assertTrue(mutations)
        for task in mutations:
            self.assertIn("not ansible_check_mode", str(task.get("when", "")),
                          f"HEC mutation lacks check-mode exclusion: {task.get('name')}")

    def test_handler_topic_has_exclusive_systemd_and_manual_paths(self):
        handlers = ARTIFACTS.yaml(self, "handlers/main.yml", list)
        owned = [task for task in handlers
                 if "splunk_server_hec_restart" in task.get("listen", [])]
        self.assertEqual(len(handlers), 2, "one handler pair must deduplicate all restart topics")
        self.assertEqual(len(owned), 2, "HEC topic needs systemd and manual restart handlers")
        self.assertTrue(all("Restart Splunk" in task.get("listen", []) for task in owned))
        conditions = "\n".join(str(task.get("when", "")) for task in owned)
        self.assertIn("splunk_server_enable_boot_start", conditions)
        self.assertRegex(conditions, r"not splunk_server_enable_boot_start")

    def test_validation_requires_redacted_http_200_and_json_code_zero(self):
        tasks = ARTIFACTS.yaml(self, "tasks/hec-validate.yml", list)
        uri_tasks = [task for task in tasks if module(task, "uri") is not None]
        self.assertTrue(uri_tasks, "missing authenticated HEC URI validation")
        self.assertTrue(all(task.get("no_log") is True for task in uri_tasks))
        self.assertTrue(any(module(task, "uri").get("status_code") == 200 for task in uri_tasks))
        uri_text = "\n".join(task_text(task) for task in uri_tasks)
        for variable in ("splunk_server_hec_validation_endpoint", "splunk_server_hec_token",
                         "splunk_server_hec_default_index", "splunk_server_hec_validate_certs",
                         "splunk_server_hec_ca_path"):
            self.assertIn(variable, uri_text, f"HEC URI validation missing {variable}")
        assertions = "\n".join(task_text(task) for task in tasks if module(task, "assert") is not None)
        self.assertRegex(assertions, r"\.json\.code\s*==\s*0|\['code'\]\s*==\s*0",
                         "validation must assert parsed HEC JSON code 0")

    def test_every_direct_token_reference_is_redacted(self):
        for name in ("tasks/hec.yml", "tasks/hec-preflight.yml", "tasks/hec-validate.yml"):
            tasks = ARTIFACTS.yaml(self, name, list)
            exposed = [task.get("name", "unnamed") for task in tasks
                       if "splunk_server_hec_token" in task_text(task) and task.get("no_log") is not True]
            self.assertFalse(exposed, f"token-bearing tasks without no_log in {name}: {exposed}")

    def test_no_debug_task_discloses_admin_password(self):
        for name in ("tasks/main.yml", "tasks/hec.yml", "tasks/hec-preflight.yml", "tasks/hec-validate.yml"):
            tasks = ARTIFACTS.yaml(self, name, list)
            debug_text = "\n".join(task_text(task) for task in tasks if module(task, "debug") is not None)
            self.assertNotIn("splunk_server_admin_password", debug_text,
                             f"debug output in {name} references the admin password")


if __name__ == "__main__":
    unittest.main()
