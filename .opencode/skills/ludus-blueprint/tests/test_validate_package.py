"""Exercise the package checker at its CLI boundary with temporary sources."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_package.py"


class PackageChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.blueprint = self.root / "blueprints" / "demo"
        self.blueprint.mkdir(parents=True)
        self.manifest = {
            "manifest_version": 1, "id": "demo", "name": "Demo",
            "description": "Example lab", "version": "1.0.0",
            "config": "range-config.yml",
        }
        self.write_manifest()
        (self.blueprint / "range-config.yml").write_text("ludus: []\n")
        (self.blueprint / "README.md").write_text("# Demo\n")

    def write_manifest(self):
        (self.blueprint / "blueprint.yml").write_text(yaml.safe_dump(self.manifest))

    def run_check(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root), "demo"],
            capture_output=True, text=True,
        )

    def test_valid_package_without_optional_source_or_requirements(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("range validation", result.stdout.lower())

    def test_missing_config_is_rejected(self):
        (self.blueprint / "range-config.yml").unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("range-config.yml", result.stderr)

    def test_external_config_and_symlink_are_rejected(self):
        outside = self.root / "outside.yml"
        outside.write_text("ludus: []\n")
        for config in ("../../outside.yml", "linked.yml"):
            with self.subTest(config=config):
                if config == "linked.yml":
                    (self.blueprint / config).symlink_to(outside)
                self.manifest["config"] = config
                self.write_manifest()
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn("inside", result.stderr)

    def test_invalid_metadata_and_requirements_have_actionable_errors(self):
        for field, value in (("id", "9bad"), ("name", ""), ("manifest_version", True)):
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = value
                self.write_manifest()
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(field, result.stderr)
                self.manifest[field] = original
        self.write_manifest()
        (self.blueprint / "requirements.yml").write_text("roles: wrong\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("roles", result.stderr)

    def test_broken_yaml_reports_error_without_traceback(self):
        (self.blueprint / "blueprint.yml").write_text("name: [\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_readme_and_misplaced_assets_are_reported(self):
        (self.blueprint / "README.md").unlink()
        (self.blueprint / "roles").mkdir()
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("README.md", result.stderr)
        self.assertIn("ansible/roles", result.stderr)


if __name__ == "__main__":
    unittest.main()
