"""Static contracts for GitLab bootstrap namespace and smoke-CI behavior.

These checks parse the role sources only. They do not call GitLab or establish
compatibility with any GitLab server or runner release.
"""

from pathlib import Path
import sys
import unittest

import yaml


REQUIRED = {"defaults/main.yml", "tasks/bootstrap.yml", "README.md"}
CI_TASKS = {
    "Construct CI file API URL",
    "Read existing CI configuration",
    "Define desired CI file content",
    "Refuse to overwrite unrelated CI configuration",
    "Create minimal Docker CI job",
    "Replace existing CI only when explicitly allowed",
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
        case.assertTrue(path.is_file(), f"Missing required runner artifact: {name} ({path})")
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


def condition_text(task):
    condition = task.get("when", "")
    return "\n".join(condition) if isinstance(condition, list) else str(condition)


class BootstrapContractStatic(unittest.TestCase):
    def setUp(self):
        self.tasks = ARTIFACTS.yaml(self, "tasks/bootstrap.yml", list)
        self.by_name = {task.get("name"): task for task in self.tasks}

    def test_required_explicit_artifacts_exist(self):
        for name in sorted(REQUIRED):
            ARTIFACTS.read(self, name)

    def test_smoke_ci_is_backward_compatible_and_enabled_by_default(self):
        defaults = ARTIFACTS.yaml(self, "defaults/main.yml", dict)
        self.assertIn("ludus_gitlab_runner_smoke_ci_enabled", defaults)
        self.assertIs(defaults["ludus_gitlab_runner_smoke_ci_enabled"], True)

    def test_absent_project_uses_single_fail_closed_namespace_lookup(self):
        lookups = [
            task for task in self.tasks
            if module(task, "uri") is not None
            and "/api/v4/namespaces/" in str(module(task, "uri").get("url", ""))
        ]
        self.assertEqual(len(lookups), 1, "absent projects require one Namespace API lookup")
        lookup = lookups[0]
        uri = module(lookup, "uri")
        self.assertEqual(
            uri.get("url"),
            "{{ ludus_gitlab_runner_api_base }}/api/v4/namespaces/"
            "{{ ludus_gitlab_runner_project_namespace | urlencode "
            "| replace('/', '%2F') }}",
            "nested namespace separators must be escaped in the path parameter",
        )
        self.assertEqual(uri.get("method"), "GET")
        self.assertEqual(uri.get("status_code"), 200)
        self.assertEqual(uri.get("headers", {}).get("PRIVATE-TOKEN"),
                         "{{ ludus_gitlab_runner_effective_api_token }}")
        self.assertIn("ludus_gitlab_runner_project_lookup.status == 404", condition_text(lookup))

        source = ARTIFACTS.read(self, "tasks/bootstrap.yml")
        self.assertNotIn("/api/v4/groups/", source)
        self.assertNotIn("/api/v4/users/", source)

    def test_namespace_identity_is_asserted_before_project_creation(self):
        validation_indexes = [
            index for index, task in enumerate(self.tasks)
            if task.get("name") == "Validate resolved namespace identity"
        ]
        creation_indexes = [
            index for index, task in enumerate(self.tasks)
            if task.get("name") == "Create project in resolved namespace when absent"
        ]
        self.assertEqual(len(validation_indexes), 1, "missing namespace identity validation")
        self.assertEqual(len(creation_indexes), 1, "missing project creation task")
        validation_index = validation_indexes[0]
        creation_index = creation_indexes[0]
        self.assertLess(validation_index, creation_index)
        validation = self.tasks[validation_index]
        assertions = module(validation, "assert").get("that", [])
        text = "\n".join(assertions)
        for contract in (
            "ludus_gitlab_runner_namespace.status == 200",
            "ludus_gitlab_runner_namespace.json.full_path == ludus_gitlab_runner_project_namespace",
            "ludus_gitlab_runner_namespace.json.kind in ['user', 'group']",
            "ludus_gitlab_runner_namespace.json.id | int > 0",
        ):
            self.assertIn(contract, text)
        self.assertIn("ludus_gitlab_runner_project_lookup.status == 404", condition_text(validation))

        creation = self.tasks[creation_index]
        namespace_id = module(creation, "uri").get("body", {}).get("namespace_id")
        self.assertEqual(namespace_id, "{{ ludus_gitlab_runner_namespace.json.id }}")

    def test_every_ci_file_operation_is_gated_by_smoke_opt_in(self):
        self.assertTrue(CI_TASKS <= set(self.by_name), f"missing CI tasks: {CI_TASKS - set(self.by_name)}")
        for name in CI_TASKS:
            self.assertIn(
                "ludus_gitlab_runner_smoke_ci_enabled",
                condition_text(self.by_name[name]),
                f"CI operation is not gated: {name}",
            )

    def test_smoke_opt_out_does_not_gate_project_or_runner_provisioning(self):
        for name in (
            "Create project in resolved namespace when absent",
            "Create runner with server-side tags",
        ):
            self.assertIn(name, self.by_name)
            self.assertNotIn("ludus_gitlab_runner_smoke_ci_enabled", condition_text(self.by_name[name]))

    def test_readme_documents_namespace_and_no_pipeline_contracts(self):
        readme = ARTIFACTS.read(self, "README.md")
        for text in (
            "ludus_gitlab_runner_smoke_ci_enabled",
            "`GET /api/v4/namespaces/:url_encoded_full_path`",
            "exact `full_path`",
            "does not read or write the CI file and launches no pipeline",
        ):
            self.assertIn(text, readme)


if __name__ == "__main__":
    unittest.main()
