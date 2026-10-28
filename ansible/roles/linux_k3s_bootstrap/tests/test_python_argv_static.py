"""Source contract for the hash-verified wheel installation argv."""

from pathlib import Path
import unittest

import yaml


PYTHON_TASKS = Path(__file__).parents[1] / "tasks" / "python.yml"
WHEEL_TASK = "Install only hash-verified wheels into the dedicated environment"


class PythonArgvStatic(unittest.TestCase):
    def test_hash_verified_wheel_task_has_only_string_argv_items(self):
        tasks = yaml.safe_load(PYTHON_TASKS.read_text(encoding="utf-8"))
        matches = [task for task in tasks if task.get("name") == WHEEL_TASK]
        self.assertEqual(len(matches), 1, "expected one hash-verified wheel installation task")
        command = matches[0].get("ansible.builtin.command", matches[0].get("command", {}))
        argv = command.get("argv")
        self.assertIsInstance(argv, list)
        self.assertTrue(
            all(isinstance(argument, str) for argument in argv),
            f"wheel installation argv must contain only strings: {argv!r}",
        )
        self.assertIn("--only-binary=:all:", argv)
        for required in ("--require-hashes", "--ignore-installed", "--requirement"):
            self.assertIn(required, argv)


if __name__ == "__main__":
    unittest.main()
