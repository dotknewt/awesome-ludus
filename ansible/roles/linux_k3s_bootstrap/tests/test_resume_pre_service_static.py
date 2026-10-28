"""Source-only contracts for the narrowly owned pre-service resume path."""

from pathlib import Path
import ast
import unittest

import yaml


ROLE = Path(__file__).parents[1]
STATE_NAME = "ludus_k3s_bootstrap_install_state"
PRE_SERVICE_PATHS = (
    "ludus_k3s_bootstrap_k3s_binary",
    "ludus_k3s_bootstrap_helm_binary",
    "ludus_k3s_bootstrap_root_helm_plugins",
    "ludus_k3s_bootstrap_helm_diff_binary",
    "ludus_k3s_bootstrap_helm_diff_manifest",
    "ludus_k3s_bootstrap_python_root",
    "ludus_k3s_bootstrap_requirements",
    "ludus_k3s_bootstrap_python_lock_verifier",
    "ludus_k3s_bootstrap_cache_dir",
    "ludus_k3s_bootstrap_cached_k3s",
    "ludus_k3s_bootstrap_helm_archive",
    "ludus_k3s_bootstrap_helm_diff_archive",
    "ludus_k3s_bootstrap_owner_dir",
)
SERVICE_PATHS = (
    "ludus_k3s_bootstrap_unit_path",
    "ludus_k3s_bootstrap_config_dir",
    "ludus_k3s_bootstrap_kubeconfig",
    "ludus_k3s_bootstrap_data_dir",
)
INSPECTOR = ROLE / "files" / "inspect_python_venv.py"


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


def read_source(case, path):
    case.assertTrue(path.is_file(), f"missing required source: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        case.fail(f"unable to read source {path}: {exc}")


def read_tasks(case, relative_path):
    source_path = ROLE / relative_path
    source = read_source(case, source_path)
    try:
        tasks = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        case.fail(f"malformed YAML in {relative_path}: {exc}")
    case.assertIsInstance(tasks, list, f"expected task list in {relative_path}")
    return tasks


class ResumePreServiceStatic(unittest.TestCase):
    def test_internal_install_state_is_published_after_preflight(self):
        main = read_tasks(self, "tasks/main.yml")
        preflight = read_tasks(self, "tasks/preflight.yml")
        writers = []
        for source_name, tasks in (("tasks/main.yml", main), ("tasks/preflight.yml", preflight)):
            for index, task in enumerate(tasks):
                facts = module(task, "set_fact") or {}
                if STATE_NAME in facts:
                    writers.append((source_name, index, task, facts[STATE_NAME]))
        self.assertEqual(len(writers), 1, f"expected one writer for {STATE_NAME}")
        source_name, index, task, state_value = writers[0]
        state_source = str(state_value) + " " + str(task.get("when", ""))
        for state in ("fresh", "complete", "resume_pre_service"):
            self.assertIn(state, state_source)

        if source_name == "tasks/main.yml":
            preflight_index = next(
                i for i, item in enumerate(main)
                if module(item, "include_tasks") == "preflight.yml"
            )
            self.assertGreater(index, preflight_index)
        else:
            identity_index = next(
                i for i, item in enumerate(preflight)
                if item.get("name") == "Require the exact owned identity"
            )
            self.assertGreater(index, identity_index)

        preflight_source = "\n".join(str(task) for task in preflight)
        for path_name in PRE_SERVICE_PATHS + SERVICE_PATHS:
            self.assertIn(path_name, preflight_source)
        for systemd_state in (
            "LoadState=not-found", "ActiveState=inactive", "SubState=dead",
            "FragmentPath=", "DropInPaths=", "Environment=", "EnvironmentFiles=",
        ):
            self.assertIn(systemd_state, preflight_source)

    def test_main_routes_resume_around_artifacts_but_into_python_and_service(self):
        main = read_tasks(self, "tasks/main.yml")
        includes = {
            module(task, "include_tasks"): task
            for task in main if module(task, "include_tasks")
        }
        self.assertIn("artifacts.yml", includes)
        self.assertIn("python.yml", includes)
        self.assertIn("service.yml", includes)
        artifact_gate = str(includes["artifacts.yml"].get("when", ""))
        python_gate = str(includes["python.yml"].get("when", ""))
        self.assertIn(STATE_NAME, artifact_gate)
        self.assertIn("fresh", artifact_gate)
        self.assertNotIn("resume_pre_service", artifact_gate)
        self.assertIn(STATE_NAME, python_gate)
        self.assertIn("fresh", python_gate)
        self.assertIn("resume_pre_service", python_gate)

    def test_systemd_resume_accepts_missing_or_empty_environment_files_in_expression(self):
        preflight = read_tasks(self, "tasks/preflight.yml")
        classifier = next(task for task in preflight if task.get("name") == "Classify the owned installation shape without publishing install state")
        variables = classifier.get("vars", {})
        self.assertNotIn("ludus_k3s_bootstrap_environment_files", variables)
        resume_expression = str(variables["ludus_k3s_bootstrap_systemd_resume_safe"])
        self.assertIn("regex_search('(?m)^EnvironmentFiles=.+$')) is none", resume_expression)
        self.assertNotIn("== 'EnvironmentFiles='", resume_expression)

    def test_resume_inspects_venv_with_trusted_system_python_and_stdin_source(self):
        inspector_source = read_source(self, INSPECTOR)
        preflight = read_tasks(self, "tasks/preflight.yml")
        python_tasks = read_tasks(self, "tasks/python.yml")
        all_tasks = preflight + python_tasks
        candidates = [
            task for task in all_tasks
            if module(task, "command") and "stdin" in module(task, "command")
        ]
        inspections = []
        for task in candidates:
            argv = module(task, "command").get("argv", [])
            if "/usr/bin/python3" in argv and "-" in argv:
                inspections.append(task)
        self.assertEqual(len(inspections), 1, "expected one stdin-fed trusted-Python inspector")
        inspect_task = inspections[0]
        argv = module(inspect_task, "command")["argv"]
        self.assertTrue(all(isinstance(item, str) for item in argv), f"inspector argv must contain only strings: {argv!r}")
        for option in ("-I", "-S", "-B"):
            self.assertIn(option, argv)
        self.assertIn("inspect_python_venv.py", str(module(inspect_task, "command")["stdin"]))
        self.assertIn("lookup(", str(module(inspect_task, "command")["stdin"]))
        self.assertIn("resume_pre_service", str(inspect_task.get("when", "")))

        for contract in (
            "pyvenv.cfg", "3.12", "system-site-packages", "pip", "24.0",
            "site-packages", "dist-info", "RECORD", "sha256", ".pth", "pyc",
            "symlink", "duplicate", "unknown", "unmanaged",
        ):
            self.assertIn(contract, inspector_source)
        for forbidden in ("subprocess", "runpy", "import_module(", "__import__("):
            self.assertNotIn(forbidden, inspector_source)
        self.assertNotIn("_getframe", inspector_source)
        self.assertIn("def reject(reason, path, expected, actual):", inspector_source)
        self.assertIn("def generated_cache_source(relative):", inspector_source)
        self.assertIn("def valid_generated_cache(relative, target, hash_verified_sources):", inspector_source)
        self.assertIn("hash_verified_python_sources = set()", inspector_source)
        self.assertIn("pending_caches = []", inspector_source)
        self.assertLess(
            inspector_source.index("hash_verified_python_sources = set()"),
            inspector_source.index("for relative, target in pending_caches:"),
            "unhashed pip caches must be checked after source hashes are verified",
        )
        inspector_tree = ast.parse(inspector_source)
        reject_calls = [
            node for node in ast.walk(inspector_tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "reject"
        ]
        self.assertTrue(reject_calls)
        self.assertTrue(
            all(len(call.args) == 4 and not call.keywords for call in reject_calls),
            "every reject call must supply reason, path, expected, and actual",
        )
        self.assertIn('cache_relative = os.path.relpath(path, site_packages)', inspector_source)
        self.assertIn('generated_cache_source(cache_relative)', inspector_source)

    def test_resume_skips_artifact_and_venv_recreation_but_installs_locked_wheels(self):
        python_tasks = read_tasks(self, "tasks/python.yml")
        create_or_copy = [
            task for task in python_tasks
            if module(task, "file") or module(task, "copy")
            or task.get("name") == "Create the isolated Python environment with Ubuntu system packages visible"
        ]
        for task in create_or_copy:
            self.assertIn("fresh", str(task.get("when", "")), task.get("name", ""))
            self.assertNotIn("resume_pre_service", str(task.get("when", "")))

        wheel_task = next(
            task for task in python_tasks
            if task.get("name") == "Install only hash-verified wheels into the dedicated environment"
        )
        wheel_condition = str(wheel_task.get("when", ""))
        self.assertIn("resume_pre_service", wheel_condition)
        argv = module(wheel_task, "command").get("argv", [])
        self.assertIn("--require-hashes", argv)
        self.assertIn("--only-binary=:all:", argv)
        self.assertIn("--ignore-installed", argv)
        self.assertNotIn("--upgrade", argv)
        self.assertNotIn("pip install --upgrade", str(wheel_task))
        for redirected in ("PIP_TARGET", "PIP_PREFIX", "PIP_USER"):
            self.assertIn(redirected, str(wheel_task))

    def test_resume_rechecks_all_service_paths_immediately_before_service_mutation(self):
        service = read_tasks(self, "tasks/service.yml")
        first_mutation = next(
            i for i, task in enumerate(service)
            if any(module(task, action) for action in ("file", "template", "systemd_service"))
        )
        guards = [
            (i, task) for i, task in enumerate(service[:first_mutation])
            if task.get("name") and "resume_pre_service" in str(task)
        ]
        self.assertTrue(guards, "missing resume boundary recheck before service writes")
        guard_index, guard = guards[-1]
        self.assertEqual(guard_index, first_mutation - 1, "service recheck must immediately precede mutation")
        guard_source = str(guard)
        for path_name in SERVICE_PATHS:
            self.assertIn(path_name, guard_source)
        for systemd_state in ("LoadState=not-found", "ActiveState=inactive", "SubState=dead"):
            self.assertIn(systemd_state, guard_source)

    def test_expected_modes_uses_evaluated_variable_keys_and_preserves_modes(self):
        preflight = read_tasks(self, "tasks/preflight.yml")
        guard = next(
            task for task in preflight
            if task.get("name") == "Require exact types modes and ownership on protected destinations"
        )
        expression = guard["vars"]["ludus_k3s_bootstrap_expected_modes"]
        self.assertIsInstance(expression, str)
        self.assertTrue(expression.strip().startswith("{{ {"))
        self.assertTrue(expression.strip().endswith("} }}"))
        expected = {
            "ludus_k3s_bootstrap_k3s_binary": "0755",
            "ludus_k3s_bootstrap_helm_binary": "0755",
            "ludus_k3s_bootstrap_unit_path": "0644",
            "ludus_k3s_bootstrap_config_dir": "0700",
            "ludus_k3s_bootstrap_kubeconfig": "0600",
            "ludus_k3s_bootstrap_data_dir": "0700",
            "ludus_k3s_bootstrap_root_helm_plugins": "0755",
            "ludus_k3s_bootstrap_helm_diff_binary": "0755",
            "ludus_k3s_bootstrap_helm_diff_manifest": "0644",
            "ludus_k3s_bootstrap_python_root": "0755",
            "ludus_k3s_bootstrap_requirements": "0644",
            "ludus_k3s_bootstrap_python_lock_verifier": "0644",
            "ludus_k3s_bootstrap_cache_dir": "0700",
            "ludus_k3s_bootstrap_cached_k3s": "0500",
            "ludus_k3s_bootstrap_helm_archive": "0600",
            "ludus_k3s_bootstrap_helm_diff_archive": "0600",
            "ludus_k3s_bootstrap_owner_dir": "0700",
        }
        self.assertEqual(len(expected), 17)
        self.assertEqual(expression.count(":"), 17)
        for key, mode in expected.items():
            expression_key = (
                f"({key} ~ '/diff')"
                if key == "ludus_k3s_bootstrap_root_helm_plugins" else key
            )
            self.assertIn(f"{expression_key}: '{mode}'", expression)

    def test_environment_files_guards_match_systemctl_empty_array_contract(self):
        preflight = read_tasks(self, "tasks/preflight.yml")
        service = read_tasks(self, "tasks/service.yml")
        verify = read_tasks(self, "tasks/verify.yml")
        collectors = (
            (preflight, "ludus_k3s_bootstrap_systemd_identity", ("LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths", "Environment", "EnvironmentFiles")),
            (service, "ludus_k3s_bootstrap_service_boundary_systemd", ("LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths", "Environment", "EnvironmentFiles")),
            (verify, "ludus_k3s_bootstrap_exec_start", ("ExecStart", "DropInPaths", "Environment", "EnvironmentFiles")),
        )
        for tasks, register, properties in collectors:
            collector = next(task for task in tasks if task.get("register") == register)
            argv = module(collector, "command").get("argv", [])
            self.assertIn("systemctl", argv)
            for prop in properties:
                self.assertIn(f"--property={prop}", argv)

        guards = (
            (preflight, "Classify the owned installation shape without publishing install state", "ludus_k3s_bootstrap_systemd_resume_safe"),
            (preflight, "Require the exact existing K3s service unit", None),
            (service, "Require the exact untouched pre-service boundary", None),
            (verify, "Require embedded containerd service configuration", None),
        )
        predicate = "regex_search('(?m)^EnvironmentFiles=.+$')) is none"
        for tasks, name, var_name in guards:
            task = next(task for task in tasks if task.get("name") == name)
            if var_name:
                source = str(task.get("vars", {}).get(var_name, ""))
            else:
                source = str(module(task, "assert").get("that", []))
            self.assertIn(predicate, source, name)
            self.assertNotIn("EnvironmentFiles=.*$')) is none or", source, name)
            self.assertNotIn("EnvironmentFiles=$')) is not none", source, name)

        preflight_source = str(preflight)
        self.assertNotIn("ludus_k3s_bootstrap_environment_files", preflight_source)
        resume_source = str(next(task for task in preflight if task.get("name") == guards[0][1]).get("vars", {}).get(guards[0][2], ""))
        self.assertIn("ludus_k3s_bootstrap_systemd_identity.rc == 0", resume_source)
        for required in ("LoadState=not-found", "ActiveState=inactive", "SubState=dead", "FragmentPath=", "DropInPaths=", "Environment="):
            self.assertIn(required, resume_source)
        boundary = str(module(next(task for task in service if task.get("name") == guards[2][1]), "assert").get("that", []))
        self.assertIn("ludus_k3s_bootstrap_service_boundary_systemd.rc == 0", boundary)
        for required in ("LoadState=not-found", "ActiveState=inactive", "SubState=dead", "FragmentPath=", "DropInPaths=", "Environment="):
            self.assertIn(required, boundary)
        unit_assertion = str(module(next(task for task in preflight if task.get("name") == guards[1][1]), "assert").get("that", []))
        self.assertIn("FragmentPath=", unit_assertion)
        self.assertIn("DropInPaths=", unit_assertion)
        verify_assertion = str(module(next(task for task in verify if task.get("name") == guards[3][1]), "assert").get("that", []))
        for required in ("/usr/local/bin/k3s server", "--docker", "--container-runtime-endpoint", "DropInPaths=", "Environment="):
            self.assertIn(required, verify_assertion)


if __name__ == "__main__":
    unittest.main()
