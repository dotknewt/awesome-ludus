import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts" / "validate.py"
SPEC = importlib.util.spec_from_file_location("ansible_validate", SCRIPT)
validate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = validate
SPEC.loader.exec_module(validate)


class ValidatorTests(unittest.TestCase):
    def make_role(self, root: Path, name: str = "sample", harness: bool = True) -> Path:
        role = root / "ansible" / "roles" / name
        (role / "tasks").mkdir(parents=True)
        (role / "tasks" / "main.yml").write_text("---\n- name: No operation\n  ansible.builtin.debug:\n    msg: ok\n")
        if harness:
            (role / "tests").mkdir()
            (role / "tests" / "syntax.yml").write_text("---\n- name: Syntax\n  hosts: localhost\n")
        return role

    def test_explicit_targets_are_classified_by_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            role = self.make_role(root)
            playbook = root / "deploy.yml"
            data = root / "source.yml"
            playbook.write_text("---\n- name: Deploy\n  hosts: localhost\n")
            data.write_text("---\nname: source\n")

            args = validate.parse_args(
                ["--role", str(role), "--playbook", str(playbook), "--data", str(data)], root
            )
            inventory = validate.build_inventory(args, root)

            self.assertEqual(inventory.syntax_targets, (role / "tests" / "syntax.yml", playbook))
            self.assertEqual(inventory.ansible_lint_targets, (role, playbook))
            self.assertEqual(
                inventory.yaml_targets,
                (role / "tasks" / "main.yml", role / "tests" / "syntax.yml", playbook, data),
            )
            self.assertEqual(inventory.coverage_errors, ())

    def test_invalid_explicit_paths_and_malformed_scope_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(validate.InvocationError):
                validate.parse_args([], root)
            with self.assertRaises(validate.InvocationError):
                validate.parse_args(["--data", str(root / "missing.yml")], root)
            data = root / "data.yml"
            data.write_text("---\nok: true\n")
            with self.assertRaises(validate.InvocationError):
                validate.parse_args(["--all", "--data", str(data)], root)

    def test_all_discovers_repository_roles_playbooks_and_artifact_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            role = self.make_role(root, "ludus_bridge_promisq")
            template_playbook = root / "templates" / "linux" / "ansible" / "reset.yml"
            template_playbook.parent.mkdir(parents=True)
            template_playbook.write_text("---\n- name: Reset\n  hosts: all\n")
            source = root / "source.yml"
            source.write_text("---\nname: source\n")
            role_playbook = role / "ludus-configure-bridge.yaml"
            role_playbook.write_text("---\n- name: Configure bridge\n  hosts: all\n")
            unknown_root_yaml = root / "notes.yaml"
            unknown_root_yaml.write_text("---\nkind: notes\n")
            (root / ".yamllint.yml").write_text("---\nextends: default\n")
            blueprint = root / "blueprints" / "lab" / "range-config.yml"
            blueprint.parent.mkdir(parents=True)
            blueprint.write_text("---\nludus: []\n")
            collection = root / "ansible" / "collections" / "example" / "galaxy.yml"
            collection.parent.mkdir(parents=True)
            collection.write_text("---\nnamespace: example\n")
            ignored_skill = root / ".opencode" / "skills" / "fixture.yml"
            ignored_skill.parent.mkdir(parents=True)
            ignored_skill.write_text("---\nignored: true\n")
            ignored_venv = root / ".venv" / "package" / "fixture.yml"
            ignored_venv.parent.mkdir(parents=True)
            ignored_venv.write_text("---\nignored: true\n")

            inventory = validate.build_inventory(validate.parse_args(["--all"], root), root)

            self.assertEqual(inventory.roles, (role,))
            self.assertEqual(inventory.playbooks, (role_playbook, template_playbook))
            self.assertIn(role_playbook, inventory.syntax_targets)
            self.assertEqual(inventory.data, (source, collection, blueprint, unknown_root_yaml))
            self.assertNotIn(unknown_root_yaml, inventory.syntax_targets)
            self.assertNotIn(ignored_skill, inventory.yaml_targets)
            self.assertNotIn(ignored_venv, inventory.yaml_targets)

    def test_all_excludes_allowlisted_symlinks_that_resolve_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory) / "outside.yml"
            outside.write_text("---\noutside: true\n")
            linked = root / "blueprints" / "lab" / "linked.yml"
            linked.parent.mkdir(parents=True)
            linked.symlink_to(outside)

            inventory = validate.build_inventory(validate.parse_args(["--all"], root), root)

            self.assertNotIn(linked, inventory.data)
            self.assertNotIn(linked, inventory.yaml_targets)

    def test_missing_harness_and_supplied_gap_are_distinct_coverage_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            role = self.make_role(root, harness=False)
            args = validate.parse_args(
                ["--role", str(role), "--coverage-gap", "external role unavailable"], root
            )

            inventory = validate.build_inventory(args, root)

            self.assertEqual(
                inventory.coverage_errors,
                (f"missing syntax harness: {role / 'tests' / 'syntax.yml'}", "external role unavailable"),
            )

    def test_ansible_lint_command_is_offline_and_configs_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            role = self.make_role(root, "role with spaces")
            inventory = validate.build_inventory(validate.parse_args(["--role", str(role)], root), root)

            commands = validate.build_commands("ansible-lint", "/tools/ansible-lint", inventory, root)

            self.assertEqual(
                commands,
                (("/tools/ansible-lint", "--offline", "-c", str(root / ".ansible-lint"), str(role)),),
            )

    def test_role_search_path_contains_only_supplied_role_parents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make_role(root, "first")
            second_parent = root / "vendor" / "roles"
            second = second_parent / "second"
            (second / "tests").mkdir(parents=True)
            (second / "tests" / "syntax.yml").write_text("---\n- hosts: localhost\n")
            args = validate.parse_args(["--role", str(first), "--role", str(second)], root)
            inventory = validate.build_inventory(args, root)

            env = validate.tool_environment(inventory, {"PATH": "/bin", "ANSIBLE_ROLES_PATH": "/old"})

            self.assertEqual(env["ANSIBLE_ROLES_PATH"], os.pathsep.join((str(first.parent), str(second.parent))))

    def test_status_aggregation_covers_all_partial_none_failure_and_coverage(self):
        passed = validate.ToolResult("x", "/bin/x", "PASS", (), "1 check")
        missing = validate.ToolResult("x", None, "NOT AVAILABLE", (), "not found")
        failed = validate.ToolResult("x", "/bin/x", "FAIL", (), "exit 2")

        self.assertEqual(validate.aggregate_status((passed, passed, passed), ()), ("PASS", 0))
        self.assertEqual(
            validate.aggregate_status((passed, missing, passed), ()),
            ("PASS WITH WARNINGS — NOT VERIFIED", 0),
        )
        self.assertEqual(
            validate.aggregate_status((missing, missing, missing), ()),
            ("PASS WITH WARNINGS — NOT VERIFIED", 0),
        )
        self.assertEqual(validate.aggregate_status((failed, missing, passed), ()), ("FAIL", 1))
        self.assertEqual(validate.aggregate_status((passed, passed, passed), ("gap",)), ("FAIL", 1))

    def test_available_tool_nonzero_and_launch_error_are_failures(self):
        nonzero = validate.result_from_process(
            "ansible-lint",
            "/tools/ansible-lint",
            ("role",),
            (subprocess.CompletedProcess(("ansible-lint",), 2, "", "missing collection"),),
        )
        launch_error = validate.run_commands(
            "yamllint", "/definitely/not/an/executable", (("/definitely/not/an/executable", "x.yml"),), ("x.yml",), {}
        )

        self.assertEqual(nonzero.status, "FAIL")
        self.assertIn("missing collection", nonzero.detail)
        self.assertEqual(launch_error.status, "FAIL")
        self.assertIn("could not launch", launch_error.detail)

    def test_later_launch_error_preserves_output_from_completed_commands(self):
        result = validate.run_commands(
            "ansible-playbook",
            sys.executable,
            (
                (sys.executable, "-c", "print('first syntax output')"),
                ("/definitely/not/an/executable", "--syntax-check", "second.yml"),
            ),
            ("first.yml", "second.yml"),
            os.environ,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertIn("first syntax output", result.detail)
        self.assertIn("could not launch", result.detail)

    def test_report_lists_inventory_and_distinct_target_and_planned_command_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.yml"
            second = root / "second.yml"
            first.write_text("---\none: true\n")
            second.write_text("---\ntwo: true\n")
            inventory = validate.build_inventory(
                validate.parse_args(["--data", str(first), "--data", str(second)], root), root
            )
            results = (
                validate.ToolResult("ansible-playbook", None, "NOT AVAILABLE", (), "not found"),
                validate.ToolResult("ansible-lint", None, "NOT AVAILABLE", (), "not found"),
                validate.ToolResult(
                    "yamllint", None, "NOT AVAILABLE", (str(first), str(second)), "not found"
                ),
            )

            report = validate.render_report(inventory, results, ["--data", str(first)], validate.WARNING_STATUS)

            self.assertIn(f"  - {first}", report)
            self.assertIn(f"  - {second}", report)
            self.assertIn(
                "yamllint: NOT AVAILABLE\n  executable: not found\n  targets: 2\n  planned commands: 1",
                report,
            )
            self.assertIn(
                f"  target inventory (UNVERIFIED):\n    - {first}\n    - {second}", report
            )

    def test_rerun_quotes_arguments_and_exposes_suggested_venv(self):
        command = validate.rerun_command(["--data", "a file.yml", "--coverage-gap", "role's missing"])

        self.assertEqual(
            command,
            "PATH=\"$PWD/.venv/ansible-validation/bin:$PATH\" python3 "
            ".opencode/skills/ansible-validation/scripts/validate.py --data 'a file.yml' "
            "--coverage-gap 'role'\"'\"'s missing'",
        )

    def test_cli_with_no_tools_is_warning_only_and_reports_static_live_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data.yml"
            data.write_text("---\nok: true\n")
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--data", str(data)],
                cwd=root,
                env={"PATH": ""},
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Static validation", completed.stdout)
            self.assertEqual(completed.stdout.count("NOT AVAILABLE"), 3)
            self.assertIn("PASS WITH WARNINGS — NOT VERIFIED", completed.stdout)
            self.assertNotIn("Overall status: PASS\n", completed.stdout)
            self.assertIn("Live verification: NOT RUN — requires separate authorization", completed.stdout)


if __name__ == "__main__":
    unittest.main()
