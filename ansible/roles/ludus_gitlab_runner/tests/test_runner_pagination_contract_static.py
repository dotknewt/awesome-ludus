"""Static source contracts for runner-page pagination and lab diagnostics."""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).parents[1]
PAGE_TASKS = ROLE / "tasks" / "runner-page.yml"


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


def walk_tasks(value):
    if isinstance(value, dict):
        if "name" in value:
            yield value
        for nested in value.values():
            yield from walk_tasks(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_tasks(nested)


class RunnerPaginationContractStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page_tasks = yaml.safe_load(PAGE_TASKS.read_text(encoding="utf-8"))

    def test_pagination_uses_top_level_normalized_header_and_preserves_empty(self):
        matches = [task for task in self.page_tasks if task.get("name") == "Save runner page"]
        self.assertEqual(len(matches), 1)
        save = module(matches[0], "set_fact")
        expression = save["ludus_gitlab_runner_next_page"]
        self.assertIn("ludus_gitlab_runner_current_page.get('x_next_page')", expression)
        self.assertIn("'x_next_page' in ludus_gitlab_runner_current_page", expression)
        self.assertNotIn(".headers", expression)
        self.assertIn("| string | trim", expression)
        self.assertNotIn("{%", expression)
        self.assertTrue(expression.strip().startswith("{{"))
        self.assertTrue(expression.strip().endswith("}}"))

    def test_absent_header_fallback_and_page_limit_are_preserved(self):
        save = next(task for task in self.page_tasks if task.get("name") == "Save runner page")
        expression = module(save, "set_fact")["ludus_gitlab_runner_next_page"]
        self.assertIn("ludus_gitlab_runner_current_page.json | length == 100", expression)
        self.assertIn("ludus_gitlab_runner_page | int + 1", expression)
        guard = next(task for task in self.page_tasks if task.get("name") == "Enforce runner discovery page limit")
        self.assertIn("ludus_gitlab_runner_page | int <= 100", str(module(guard, "assert")))
        for name in ("Increment runner page", "Fetch subsequent page when pagination continues"):
            continuation = next(task for task in self.page_tasks if task.get("name") == name)
            self.assertEqual(
                continuation.get("when"),
                "ludus_gitlab_runner_next_page | string | trim | length > 0",
            )

    def test_runner_tasks_do_not_blanket_suppress_diagnostics(self):
        suppressed = []
        for path in sorted((ROLE / "tasks").rglob("*.yml")):
            tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
            for task in walk_tasks(tasks):
                if task.get("no_log") is True:
                    suppressed.append(f"{path.relative_to(ROLE)}: {task.get('name')}")
        self.assertEqual(suppressed, [], "blanket no_log suppresses runner diagnostics: " + "; ".join(suppressed))

    def test_readme_discloses_disposable_lab_diagnostics_scope(self):
        readme = (ROLE / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("disposable lab", readme)
        self.assertIn("ansible diagnostics", readme)
        self.assertIn("production credentials", readme)


if __name__ == "__main__":
    unittest.main()
