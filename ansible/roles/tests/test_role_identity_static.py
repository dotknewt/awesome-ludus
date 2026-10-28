#!/usr/bin/env python3
"""Static source-local role identity and attribution contracts."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
IDENTITIES = {
    "linux_splunk_server": ("dotknewt", "linux_splunk_server"),
    "linux_gitlab_ce": ("dotknewt", "linux_gitlab_ce"),
    "linux_logging": ("dotknewt", "linux_logging"),
    "linux_gitlab_runner": ("dotknewt", "linux_gitlab_runner"),
    "linux_k3s_bootstrap": ("dotknewt", "linux_k3s_bootstrap"),
    "linux_install_docker": ("dotknewt", "linux_install_docker"),
}


class RoleIdentityStatic(unittest.TestCase):
    def test_canonical_directory_metadata_and_author(self):
        for name, (author, role_name) in IDENTITIES.items():
            with self.subTest(role=name):
                role = ROOT / "ansible" / "roles" / name
                self.assertTrue(role.is_dir(), f"missing canonical role directory {role}")
                metadata = yaml.safe_load((role / "meta" / "main.yml").read_text())
                galaxy_info = metadata.get("galaxy_info", {})
                self.assertEqual(galaxy_info.get("role_name"), role_name)
                self.assertEqual(galaxy_info.get("author"), author)


if __name__ == "__main__":
    unittest.main()
