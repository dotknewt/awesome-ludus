"""Local source resolution and staging contract checks (no Ludus server)."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from scripts.ludus_deployment import models, source
except ModuleNotFoundError as exc:
    if exc.name not in {"scripts.ludus_deployment", "scripts.ludus_deployment.models"}:
        raise
    # Keep the red phase focused on missing project APIs even before package
    # creation; unrelated optional/dependency import failures remain visible.
    from types import SimpleNamespace

    models = SimpleNamespace(__name__="scripts.ludus_deployment.models")
    source = SimpleNamespace(__name__="scripts.ludus_deployment.source")


def api(module, name):
    """Fail clearly for an unimplemented API, not for import-time dependencies."""
    value = getattr(module, name, None)
    if value is None:
        raise AssertionError(f"required production API {module.__name__}.{name} is missing")
    return value


def git(directory: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=directory, text=True).strip()


class LudusSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        api(models, "Capabilities")
        self.capabilities = models.Capabilities(
            client_version="2.3.10+fccf931e",
            server_version="2.3.10+fccf931e",
            identity_rules={},
            correlation_mode="unknown-only",
        )

    def tearDown(self):
        self.temp.cleanup()

    def checkout(self, root: Path):
        (root / "ansible/roles").mkdir(parents=True)
        git(root, "init", "-q")
        git(root, "config", "user.email", "tests@example.invalid")
        git(root, "config", "user.name", "Tests")
        (root / "ansible/roles/.keep").write_text("tracked role root\n")
        (root / "tracked").write_text("tracked\n")
        git(root, "add", "tracked", "ansible/roles/.keep")
        git(root, "commit", "-qm", "initial")

    def role(self, identity: str, metadata_name: str | None = None) -> Path:
        directory = self.root / "ansible/roles" / identity
        (directory / "meta").mkdir(parents=True, exist_ok=True)
        role_name = metadata_name or identity
        (directory / "meta/main.yml").write_text(
            f"galaxy_info:\n  author: example\n  role_name: {role_name}\n"
        )
        return directory

    def test_duplicate_keys_rejected(self):
        parse = api(source, "parse_config")
        raw = "ludus: []\nludus: []\n"
        with self.assertRaises((ValueError, TypeError)):
            parse(raw, self.capabilities)

    def test_dynamic_or_ambiguous_identity_blocks(self):
        parse = api(source, "parse_config")
        for raw in (
            "ludus:\n  - vm_name: app\n    roles: ['{{ dynamic_role }}']\n",
            "ludus:\n  - vm_name: app\n    roles:\n      - name: alpha\n        name: beta\n",
            "ludus:\n  - vm_name: app\n    roles:\n      - name: alpha\n        depends_on: [{vm_name: db}]\n",
        ):
            with self.subTest(raw=raw), self.assertRaises((ValueError, TypeError)):
                parse(raw, self.capabilities)

    def test_actual_ludus_config_collects_roles_and_vm_role_dependencies_once(self):
        parse = api(source, "parse_config")
        raw = (
            "ludus:\n"
            "  - vm_name: app\n"
            "    roles:\n"
            "      - app_role\n"
            "      - name: wrapper\n"
            "        depends_on:\n"
            "          - {vm_name: db, role: database_role}\n"
            "  - vm_name: worker\n"
            "    roles:\n"
            "      - app_role\n"
            "      - name: wrapper\n"
            "        depends_on:\n"
            "          - {vm_name: db, role: database_role}\n"
            "  - vm_name: db\n"
            "    roles: [database_role]\n"
        )
        parsed = parse(raw, self.capabilities)
        self.assertEqual(parsed.roles, ("app_role", "wrapper", "database_role"))
        import hashlib
        self.assertEqual(parsed.digest, hashlib.sha256(raw.encode()).hexdigest())

    def test_unsupported_ludus_forms_and_malformed_dependencies_block(self):
        parse = api(source, "parse_config")
        for raw in (
            "ludus: {}\n",
            "ludus: [{vm_name: app, roles: {role: app_role}}]\n",
            "ludus: [{vm_name: app, roles: [{name: app_role, depends_on: [{role: db}]}]}]\n",
            "ludus: [{vm_name: app, roles: [{name: app_role, depends_on: [{vm_name: db}]}]}]\n",
        ):
            with self.subTest(raw=raw), self.assertRaises((ValueError, TypeError)):
                parse(raw, self.capabilities)

    def test_dependency_vm_must_exist_and_assign_referenced_role(self):
        parse = api(source, "parse_config")
        for dependency, extra_vm in (
            ("{vm_name: absent, role: database_role}", ""),
            ("{vm_name: db, role: not_assigned}", "  - vm_name: db\n    roles: [database_role]\n"),
        ):
            raw = (
                "ludus:\n"
                "  - vm_name: app\n"
                "    roles:\n"
                "      - name: app_role\n"
                f"        depends_on: [{dependency}]\n"
                + extra_vm
            )
            with self.subTest(dependency=dependency), self.assertRaises((ValueError, TypeError)):
                parse(raw, self.capabilities)

    def test_identical_static_vm_templates_can_match_but_distinct_dynamic_expressions_block(self):
        parse = api(source, "parse_config")
        same = (
            "ludus:\n"
            "  - vm_name: '{{ range_id }}-db'\n"
            "    roles: [database_role]\n"
            "  - vm_name: app\n"
            "    roles:\n"
            "      - name: app_role\n"
            "        depends_on: [{vm_name: '{{ range_id }}-db', role: database_role}]\n"
        )
        self.assertIn("database_role", parse(same, self.capabilities).roles)
        different = same.replace("{{ range_id }}-db', role", "{{ other_id }}-db', role")
        with self.assertRaises((ValueError, TypeError)):
            parse(different, self.capabilities)

    def test_exact_folder_wins_despite_metadata_disagreement(self):
        exact = self.role("linux_splunk_server", "linux_splunk_enterprise")
        # Metadata is required, but its role_name is not a competing identity.
        resolve = api(source, "resolve_roles")
        config = models.ActiveConfig(digest="0" * 64, roles=("linux_splunk_server",))
        checkout = models.Checkout(root=self.root, revision=None)
        result = resolve(checkout, config, self.capabilities)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].identity, "linux_splunk_server")
        self.assertEqual(result[0].source, exact)

    def test_exact_folder_still_requires_nonempty_metadata_fields(self):
        resolve = api(source, "resolve_roles")
        for metadata in (
            "galaxy_info:\n  author: ''\n  role_name: exact_role\n",
            "galaxy_info:\n  author: example\n  role_name: ''\n",
        ):
            with self.subTest(metadata=metadata):
                role_dir = self.root / "ansible/roles/exact_role"
                (role_dir / "meta").mkdir(parents=True, exist_ok=True)
                (role_dir / "meta/main.yml").write_text(metadata)
                config = models.ActiveConfig(digest="0" * 64, roles=("exact_role",))
                with self.assertRaises((ValueError, TypeError)):
                    resolve(models.Checkout(self.root, None), config, self.capabilities)
                import shutil
                shutil.rmtree(role_dir)

    def test_missing_namespaced_folder_requires_mapping(self):
        self.role("acme.other")
        resolve = api(source, "resolve_roles")
        config = models.ActiveConfig(digest="0" * 64, roles=("acme.widget",))
        checkout = models.Checkout(root=self.root, revision=None)
        with self.assertRaises((ValueError, TypeError)) as raised:
            resolve(checkout, config, self.capabilities)
        self.assertIn("acme.widget", str(raised.exception))
        self.assertIn(str(self.root / "ansible/roles"), str(raised.exception))

    def test_valid_explicit_mapping_and_exact_folder_mapping_conflict(self):
        resolve = api(source, "resolve_roles")
        role_dir = self.role("actual_role")
        mapping = self.root / "ansible/role-identities.yml"
        mapping.write_text("schema_version: 1\nroles:\n  acme.widget: actual_role\n")
        config = models.ActiveConfig(digest="0" * 64, roles=("acme.widget",))
        result = resolve(models.Checkout(self.root, None), config, self.capabilities)
        self.assertEqual(result[0].identity, "acme.widget")
        self.assertEqual(result[0].source, role_dir)

        self.role("acme.widget")
        with self.assertRaises((ValueError, TypeError)):
            resolve(models.Checkout(self.root, None), config, self.capabilities)

    def test_missing_mapped_and_exact_roles_are_aggregated(self):
        resolve = api(source, "resolve_roles")
        (self.root / "ansible/roles").mkdir(parents=True)
        (self.root / "ansible/role-identities.yml").write_text(
            "schema_version: 1\nroles:\n  mapped_missing: absent_directory\n"
        )
        config = models.ActiveConfig(digest="0" * 64, roles=("mapped_missing", "exact_missing"))
        with self.assertRaises((ValueError, TypeError)) as raised:
            resolve(models.Checkout(self.root, None), config, self.capabilities)
        self.assertIn("mapped_missing", str(raised.exception))
        self.assertIn("exact_missing", str(raised.exception))
        self.assertIn(str(self.root / "ansible/roles"), str(raised.exception))

    def test_all_missing_configured_roles_are_reported(self):
        resolve = api(source, "resolve_roles")
        (self.root / "ansible/roles").mkdir(parents=True)
        config = models.ActiveConfig(digest="0" * 64, roles=("first_missing", "second_missing"))
        with self.assertRaises((ValueError, TypeError)) as raised:
            resolve(models.Checkout(self.root, None), config, self.capabilities)
        self.assertIn("first_missing", str(raised.exception))
        self.assertIn("second_missing", str(raised.exception))
        self.assertIn(str(self.root / "ansible/roles"), str(raised.exception))

    def test_missing_roles_has_structured_safe_diagnostic_boundary(self):
        error_type = api(source, "MissingRolesError")
        diagnostic = api(source, "safe_missing_roles_message")
        root = self.root / "ansible/roles"
        error = error_type(("credential-canary-role", "safe_missing"), root)
        self.assertEqual(error.identities, ("credential-canary-role", "safe_missing"))
        self.assertEqual(error.search_root, root)
        safe = diagnostic(error, ("safe_missing",), ("credential-canary",))
        self.assertIn("safe_missing", safe)
        self.assertIn(str(root), safe)
        self.assertNotIn("credential-canary", safe)
        self.assertNotIn("credential-canary-role", safe)
        self.assertNotIn("Traceback", safe)

    def test_archive_suffix_identity_rejected(self):
        resolve = api(source, "resolve_roles")
        for identity in ("role.tar.gz", "role.zip", "role.TGZ"):
            config = models.ActiveConfig(digest="0" * 64, roles=(identity,))
            with self.subTest(identity=identity), self.assertRaises((ValueError, TypeError)):
                resolve(models.Checkout(self.root, None), config, self.capabilities)

    def test_worktree_override_and_cwd(self):
        discover = api(source, "discover_checkout")
        base = self.root / "base"
        base.mkdir()
        self.checkout(base)
        git(base, "worktree", "add", "-qb", "feature", str(self.root / "worktree"))
        worktree = self.root / "worktree"
        from_cwd = discover(worktree, None)
        self.assertEqual(from_cwd.root.resolve(), worktree.resolve())
        from_override = discover(base, worktree)
        self.assertEqual(from_override.root.resolve(), worktree.resolve())
        self.assertNotEqual(from_cwd.root.resolve(), base.resolve())

    def test_non_git_directory_is_not_a_checkout(self):
        discover = api(source, "discover_checkout")
        non_git = self.root / "not-git"
        (non_git / "ansible/roles").mkdir(parents=True)
        with self.assertRaises((ValueError, OSError)):
            discover(non_git, None)

    def test_manifest_tracks_untracked_deletion_and_exec_bits(self):
        manifest = api(source, "manifest")
        role = self.root / "role"
        role.mkdir()
        file = role / "payload"
        file.write_text("same bytes\n")
        initial = manifest(role)
        os.utime(file, (1_000_000, 1_000_000))
        self.assertEqual(manifest(role).digest, initial.digest)
        file.chmod(0o755)
        executable = manifest(role)
        self.assertNotEqual(executable.digest, initial.digest)
        file.chmod(0o644)
        file.unlink()
        self.assertNotEqual(manifest(role).digest, initial.digest)
        file.write_text("untracked\n")
        self.assertNotEqual(manifest(role).digest, initial.digest)

    def test_symlink_escape_rejected(self):
        manifest = api(source, "manifest")
        role = self.root / "role"
        role.mkdir()
        outside = self.root / "outside"
        outside.write_text("private\n")
        (role / "escape").symlink_to(outside)
        with self.assertRaises((ValueError, OSError)):
            manifest(role)

        root_alias = self.root / "role-alias"
        root_alias.symlink_to(role, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            manifest(root_alias)

    def test_symlink_role_root_and_role_directory_rejected(self):
        resolve = api(source, "resolve_roles")
        config = models.ActiveConfig(digest="0" * 64, roles=("outside_role",))
        outside = self.root / "outside_role"
        outside.mkdir()
        (outside / "meta").mkdir()
        (outside / "meta/main.yml").write_text(
            "galaxy_info:\n  author: example\n  role_name: outside_role\n"
        )
        checkout_root = self.root / "checkout"
        (checkout_root / "ansible").mkdir(parents=True)
        (checkout_root / "ansible/roles").symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            resolve(models.Checkout(checkout_root, None), config, self.capabilities)

        clean_root = self.root / "clean-checkout"
        (clean_root / "ansible/roles").mkdir(parents=True)
        (clean_root / "ansible/roles/outside_role").symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            resolve(models.Checkout(clean_root, None), config, self.capabilities)

    def test_symlink_mapping_target_rejected(self):
        resolve = api(source, "resolve_roles")
        checkout = self.root / "mapped-checkout"
        (checkout / "ansible/roles").mkdir(parents=True)
        outside = self.root / "outside-mapped"
        outside.mkdir()
        (checkout / "ansible/roles/alias").symlink_to(outside, target_is_directory=True)
        (checkout / "ansible/role-identities.yml").write_text(
            "schema_version: 1\nroles:\n  acme.role: alias\n"
        )
        config = models.ActiveConfig(digest="0" * 64, roles=("acme.role",))
        with self.assertRaises((ValueError, OSError)):
            resolve(models.Checkout(checkout, None), config, self.capabilities)

    def test_static_role_dependencies_must_resolve_to_local_role_identities(self):
        resolve = api(source, "resolve_roles")
        for reference_file, contents in (
            ("tasks/main.yml", "- ansible.builtin.include_role:\n    name: absent_role\n"),
            ("tasks/imports.yml", "- ansible.builtin.import_role:\n    name: absent_role\n"),
            ("meta/main.yml", "galaxy_info:\n  author: example\n  role_name: primary\ndependencies:\n  - absent_role\n"),
        ):
            with self.subTest(reference_file=reference_file):
                role_dir = self.role("primary")
                path = role_dir / reference_file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
                config = models.ActiveConfig(digest="0" * 64, roles=("primary",))
                with self.assertRaises((ValueError, TypeError)) as raised:
                    resolve(models.Checkout(self.root, None), config, self.capabilities)
                self.assertIn("absent_role", str(raised.exception))
                # Remove fixture before next dependency case.
                import shutil
                shutil.rmtree(role_dir)

    def test_role_discovery_covers_action_and_block_rescue_always_positions_not_vars(self):
        resolve = api(source, "resolve_roles")
        role_dir = self.role("primary")
        (role_dir / "tasks").mkdir()
        (role_dir / "tasks/main.yml").write_text(
            "- name: vars are data, not actions\n"
            "  vars:\n"
            "    include_role: {name: data_only}\n"
            "- name: alternate action syntax\n"
            "  action: ansible.builtin.include_role\n"
            "  args: {name: absent_action_role}\n"
            "- block:\n"
            "    - import_role: {name: absent_block_role}\n"
            "  rescue:\n"
            "    - name: rescue action\n"
            "      action:\n"
            "        module: ansible.builtin.include_role\n"
            "        args: {name: absent_rescue_role}\n"
            "  always:\n"
            "    - ansible.builtin.import_role:\n"
            "        name: absent_always_role\n"
        )
        config = models.ActiveConfig(digest="0" * 64, roles=("primary",))
        with self.assertRaises((ValueError, TypeError)) as raised:
            resolve(models.Checkout(self.root, None), config, self.capabilities)
        for missing in ("absent_action_role", "absent_block_role", "absent_rescue_role", "absent_always_role"):
            self.assertIn(missing, str(raised.exception))
        self.assertNotIn("data_only", str(raised.exception))

    def test_action_mapping_top_level_name_resolves_existing_role(self):
        resolve = api(source, "resolve_roles")
        primary = self.role("primary")
        self.role("existing_role")
        tasks = primary / "tasks"
        tasks.mkdir()
        (tasks / "main.yml").write_text(
            "- name: mapping action with top-level name\n"
            "  action:\n"
            "    module: ansible.builtin.include_role\n"
            "    name: existing_role\n"
        )
        config = models.ActiveConfig(digest="0" * 64, roles=("primary",))
        resolved = resolve(models.Checkout(self.root, None), config, self.capabilities)
        self.assertEqual(tuple(role.identity for role in resolved), ("primary",))

    def test_action_mapping_top_level_name_reports_missing_role(self):
        resolve = api(source, "resolve_roles")
        primary = self.role("primary")
        tasks = primary / "tasks"
        tasks.mkdir()
        (tasks / "main.yml").write_text(
            "- action:\n"
            "    module: ansible.builtin.include_role\n"
            "    name: absent_action_role\n"
        )
        config = models.ActiveConfig(digest="0" * 64, roles=("primary",))
        with self.assertRaises((ValueError, TypeError)) as raised:
            resolve(models.Checkout(self.root, None), config, self.capabilities)
        self.assertIn("absent_action_role", str(raised.exception))

    def test_action_mapping_conflicting_nested_and_top_level_names_blocks(self):
        resolve = api(source, "resolve_roles")
        primary = self.role("primary")
        self.role("top_level_role")
        self.role("nested_role")
        tasks = primary / "tasks"
        tasks.mkdir()
        (tasks / "main.yml").write_text(
            "- action:\n"
            "    module: ansible.builtin.include_role\n"
            "    name: top_level_role\n"
            "    args: {name: nested_role}\n"
        )
        config = models.ActiveConfig(digest="0" * 64, roles=("primary",))
        with self.assertRaises((ValueError, TypeError)) as raised:
            resolve(models.Checkout(self.root, None), config, self.capabilities)
        self.assertIn("conflict", str(raised.exception).lower())

    def test_unreadable_role_subtree_is_not_silently_omitted(self):
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            self.skipTest("permission-denial behavior requires an unprivileged process")
        manifest = api(source, "manifest")
        role = self.root / "role"
        locked = role / "locked"
        locked.mkdir(parents=True)
        (locked / "hidden.txt").write_text("must not disappear from digest")
        locked.chmod(0)
        try:
            with self.assertRaises((ValueError, OSError)):
                manifest(role)
        finally:
            locked.chmod(0o700)

    def test_stage_rejects_source_churn_during_real_copy(self):
        stage_roles = api(source, "stage_roles")
        role_dir = self.role("churning")
        payload = role_dir / "payload"
        payload.write_text("before\n")
        resolved = models.ResolvedRole("churning", role_dir, ())
        copy_tree = source._copy_tree

        def copy_then_mutate(src, dst):
            copy_tree(src, dst)
            payload.write_text("after\n")

        with patch.object(source, "_copy_tree", side_effect=copy_then_mutate):
            with self.assertRaises((ValueError, OSError)):
                stage_roles((resolved,), self.root / "churn-stage")
        self.assertFalse((self.root / "churn-stage/churning").exists())

    def test_stage_rejects_symlink_ancestor_and_unsafe_role_identity(self):
        stage_roles = api(source, "stage_roles")
        role_dir = self.role("source_role")
        alias = self.root / "stage-alias"
        target = self.root / "stage-target"
        target.mkdir()
        alias.symlink_to(target, target_is_directory=True)
        resolved = models.ResolvedRole("safe_role", role_dir, ())
        with self.assertRaises((ValueError, OSError)):
            stage_roles((resolved,), alias / "child")
        for identity in ("../escaped", "nested/role", "evil.zip"):
            with self.subTest(identity=identity), self.assertRaises((ValueError, OSError)):
                stage_roles((models.ResolvedRole(identity, role_dir, ()),), self.root / "safe-stage")
        self.assertFalse((self.root / "escaped").exists())

    def test_git_environment_cannot_redirect_checkout_discovery(self):
        discover = api(source, "discover_checkout")
        actual = self.root / "actual"
        actual.mkdir()
        self.checkout(actual)
        decoy = self.root / "decoy"
        decoy.mkdir()
        self.checkout(decoy)
        with patch.dict(os.environ, {"GIT_DIR": str(decoy / ".git")}):
            try:
                checkout = discover(actual, None)
            except ValueError:
                return  # Explicit rejection of unsafe Git environment is valid.
        self.assertEqual(checkout.root.resolve(), actual.resolve())

    def test_stage_matches_complete_source_manifest(self):
        stage_roles = api(source, "stage_roles")
        manifest = api(source, "manifest")
        role_dir = self.role("example")
        (role_dir / "untracked.txt").write_text("included\n")
        (role_dir / "run.sh").write_text("#!/bin/sh\n")
        (role_dir / "run.sh").chmod(0o755)
        (role_dir / "__pycache__").mkdir()
        (role_dir / "__pycache__/ignored.pyc").write_bytes(b"cache")
        (role_dir / "ignored.pyc").write_bytes(b"cache")
        (role_dir / ".git").mkdir()
        (role_dir / ".git/config").write_text("not staged")
        resolved = models.ResolvedRole("example", role_dir, ())
        staged = stage_roles((resolved,), self.root / "stage")
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].manifest, manifest(role_dir))
        self.assertTrue((staged[0].directory / "untracked.txt").exists())
        self.assertEqual((staged[0].directory / "run.sh").stat().st_mode & 0o111, 0o111)
        self.assertFalse((staged[0].directory / "ignored.pyc").exists())
        self.assertFalse((staged[0].directory / "__pycache__").exists())
        self.assertFalse((staged[0].directory / ".git").exists())
        self.assertEqual(stat.S_IMODE((self.root / "stage").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(staged[0].directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((staged[0].directory / "run.sh").stat().st_mode), 0o711)
        (staged[0].directory / "untracked.txt").write_text("tampered\n")
        self.assertNotEqual(manifest(staged[0].directory), staged[0].manifest)


if __name__ == "__main__":
    unittest.main()
