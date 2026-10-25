"""Static source contracts for the GitLab bootstrap privilege split.

These checks inspect source only; they do not run Ansible, Rails, or a guest.
"""

from pathlib import Path
import re
import unittest

import yaml


ROLE = Path(__file__).parents[1]
TASKS = ROLE / "tasks" / "bootstrap.yml"
WRAPPER = ROLE / "files" / "bootstrap_api_token.rb"
RAILS_HELPER = ROLE / "files" / "bootstrap_api_token_rails.rb"
TOKEN_FILE = "{{ ludus_gitlab.bootstrap.token_file | default('/var/lib/ludus/gitlab/bootstrap-api-token') }}"
DEST = "/usr/local/sbin/ludus-gitlab-bootstrap-api-token.rb"
RAILS_DEST = "/usr/local/sbin/ludus-gitlab-bootstrap-api-token-rails.rb"


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


class BootstrapPrivilegeSplitStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.rails_helper_exists = RAILS_HELPER.is_file()
        cls.rails = RAILS_HELPER.read_text(encoding="utf-8") if cls.rails_helper_exists else ""

    def test_installs_wrapper_and_readable_nonsecret_rails_helper(self):
        self.assertTrue(self.rails_helper_exists, f"missing Rails helper source: {RAILS_HELPER}")
        copies = {
            module(task, "copy").get("src"): module(task, "copy")
            for task in self.tasks
            if module(task, "copy")
        }
        self.assertEqual(
            copies.get("bootstrap_api_token.rb"),
            {
                "src": "bootstrap_api_token.rb",
                "dest": DEST,
                "owner": "root",
                "group": "root",
                "mode": "0700",
            },
        )
        self.assertEqual(
            copies.get("bootstrap_api_token_rails.rb"),
            {
                "src": "bootstrap_api_token_rails.rb",
                "dest": RAILS_DEST,
                "owner": "root",
                "group": "root",
                "mode": "0644",
            },
        )

    def test_root_task_invokes_only_embedded_ruby_wrapper_without_override(self):
        matches = [
            task for task in self.tasks
            if task.get("name") == "(GITLAB-CE) Generate or validate delegated bootstrap credential"
        ]
        self.assertEqual(len(matches), 1)
        task = matches[0]
        self.assertEqual(
            module(task, "command"),
            {"argv": ["/opt/gitlab/embedded/bin/ruby", DEST, TOKEN_FILE]},
        )
        self.assertIs(task.get("become"), True)
        self.assertIs(task.get("no_log"), True)
        self.assertNotIn("environment", task)
        self.assertNotIn("NO_PRIVILEGE_DROP", "\n".join(map(str, self.tasks)))

    def test_wrapper_uses_vendor_runner_and_clears_privilege_override(self):
        for source in (
            "gitlab-rails",
            "runner",
            RAILS_DEST,
            "NO_PRIVILEGE_DROP",
            "SecureRandom.hex(32)",
            "File.link(temporary_path, token_path)",
            "fsync_directory",
            "IO.pipe",
            "IO.select",
            "read_nonblock",
            "write_nonblock",
            "LOCK_NB",
            "output == expected",
            "status&.success?",
        ):
            self.assertIn(source, self.wrapper)
        self.assertRegex(self.wrapper, r"[\"']NO_PRIVILEGE_DROP[\"']\s*=>\s*nil")
        self.assertIn("LUDUS_BOOTSTRAP_V1 #{mode == 'create' ? 'CREATED' : 'VALIDATED'}\\n", self.wrapper)
        self.assertNotIn("Thread.new", self.wrapper)
        for forbidden in ("capture3", "system(", "exec(", "puts token", "STDERR.puts", "Fiddle"):
            self.assertNotIn(forbidden, self.wrapper)

    def test_rails_helper_is_filesystem_free_and_reports_only_postcommit_marker(self):
        self.assertIn("Process.euid.zero?", self.rails)
        self.assertIn("LUDUS_BOOTSTRAP_V1 CREATED", self.rails)
        self.assertIn("LUDUS_BOOTSTRAP_V1 VALIDATED", self.rails)
        self.assertIn("PersonalAccessToken.find_by_token", self.rails)
        self.assertIn("named_tokens.exists?", self.rails)
        self.assertIn("stored.user_id == root.id", self.rails)
        self.assertIn("stored.name == token_name", self.rails)
        self.assertIn("!stored.revoked?", self.rails)
        self.assertIn("!stored.expired?", self.rails)
        self.assertIn("(required_scopes - stored.scopes.map(&:to_s)).empty?", self.rails)
        self.assertIn("personal_access_tokens.build", self.rails)
        self.assertIn("set_token", self.rails)
        self.assertIn("pat.save!", self.rails)
        self.assertIn("transaction", self.rails)
        self.assertIn("365.days.from_now", self.rails)
        self.assertIn("create_runner", self.rails)
        rails_code = "\n".join(line.split("#", 1)[0] for line in self.rails.splitlines())
        self.assertNotRegex(rails_code, r"\b(?:File|IO|Pathname)\s*[.(\[]")
        self.assertNotRegex(self.rails, r"(?:puts|print|warn)\s+.*(?:token|raw_token)")
        self.assertRegex(self.rails, r"\(required_scopes\s*-\s*[^)]*scopes|scopes[^\n]*required_scopes")
        self.assertNotRegex(self.rails, r"scopes\s*==\s*required_scopes")
        self.assertIn("STDIN.read(4097)", self.rails)
        self.assertIn(".strip", self.rails)

    def test_wrapper_preserves_existing_nonempty_opaque_credentials(self):
        self.assertIn("Process.euid.zero?", self.wrapper)
        self.assertIn("file.read(4097)", self.wrapper)
        self.assertIn("value.strip", self.wrapper)
        existing_check = self.wrapper.split("def validate_credential_stat", 1)[1].split(
            "\ndef validate_new_credential_stat", 1
        )[0]
        self.assertNotIn("gid", existing_check)
        self.assertNotIn("nlink", existing_check)

    def test_errors_are_allowlisted_before_ansible_failure_message(self):
        task_source = TASKS.read_text(encoding="utf-8")
        wrapper_categories = set(re.search(
            r"BOOTSTRAP_ERROR_CATEGORIES\s*=\s*%w\[(.*?)\]\.freeze", self.wrapper, re.S
        ).group(1).split())
        rails_categories = set(re.search(
            r"RAILS_ERROR_CATEGORIES\s*=\s*%w\[(.*?)\]\.freeze", self.wrapper, re.S
        ).group(1).split())
        helper_categories = set(re.search(
            r"RAILS_ERROR_CATEGORIES\s*=\s*%w\[(.*?)\]\.freeze", self.rails, re.S
        ).group(1).split())
        task_allowlist = re.search(r"select\('in', \[(.*?)\]\)", task_source, re.S).group(1)
        task_categories = set(re.findall(r"'([a-z_]+)'", task_allowlist))
        self.assertEqual(rails_categories, helper_categories)
        self.assertLessEqual(rails_categories, wrapper_categories)
        self.assertEqual(wrapper_categories, task_categories)
        self.assertIn("default('unknown', true)", task_source)
        self.assertNotIn("linux_gitlab_ce_bootstrap_result.stderr }}", task_source)


if __name__ == "__main__":
    unittest.main()
