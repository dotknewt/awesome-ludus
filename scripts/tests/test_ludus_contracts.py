"""Static Ludus CLI and capability-boundary contracts; never contacts a server."""

from __future__ import annotations

import ast
import os
from dataclasses import replace
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts import ludus_deploy
from scripts.ludus_deployment import ludus, state
from scripts.ludus_deployment import models
from scripts.ludus_deployment import workflow

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "scripts" / "ludus_deployment" / "ludus.py"
WORKFLOW = ROOT / "scripts" / "ludus_deployment" / "workflow.py"
CLI = ROOT / "scripts" / "ludus_deploy.py"


def adapter_tree() -> ast.Module:
    if not ADAPTER.is_file():
        raise AssertionError("required production adapter scripts/ludus_deployment/ludus.py is missing")
    return ast.parse(ADAPTER.read_text(encoding="utf-8"), filename=str(ADAPTER))


def class_node(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"required adapter class {name} is missing")


def source_segment(node: ast.AST) -> str:
    """Extract a class/function's local source from the parsed adapter AST."""
    return ast.get_source_segment(ADAPTER.read_text(encoding="utf-8"), node) or ""


def workflow_tree() -> ast.Module:
    if not WORKFLOW.is_file():
        raise AssertionError("required production workflow scripts/ludus_deployment/workflow.py is missing")
    return ast.parse(WORKFLOW.read_text(encoding="utf-8"), filename=str(WORKFLOW))


def cli_tree() -> ast.Module:
    if not CLI.is_file():
        raise AssertionError("required CLI scripts/ludus_deploy.py is missing")
    return ast.parse(CLI.read_text(encoding="utf-8"), filename=str(CLI))


def function_node(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"required workflow function {name} is missing")


class LudusContractTests(unittest.TestCase):
    def test_local_yaml_config_extensions_and_case_preserve_target_and_tls(self):
        for filename in ("config.yml", "config.yaml"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as home:
                directory = Path(home) / ".config/ludus"
                directory.mkdir(parents=True)
                (directory / filename).write_text("URL: https://configured.invalid\nVERIFY: true\n")
                with patch.dict(os.environ, {"HOME": home}, clear=True):
                    settings = ludus._resolve_settings({}, ludus._load_config())
                self.assertEqual(settings, ("https://configured.invalid", "", True))

    def test_ambiguous_or_unsupported_local_config_blocks_without_payload(self):
        for files in (
            {"config.yml": "url: https://one.invalid\n", "config.yaml": "url: https://two.invalid\n"},
            {"config.yml": "verify: false\nVERIFY: true\n"},
            {"config.yml": "url: https://one.invalid\nurl: https://two.invalid\n"},
            {"config.json": '{"url":"https://configured.invalid","verify":true}'},
        ):
            with self.subTest(files=tuple(files)), tempfile.TemporaryDirectory() as home:
                directory = Path(home) / ".config/ludus"
                directory.mkdir(parents=True)
                for filename, content in files.items():
                    (directory / filename).write_text(content)
                with patch.dict(os.environ, {"HOME": home}, clear=True):
                    with self.assertRaises(ludus.LudusAdapterError) as raised:
                        ludus._load_config()
                self.assertEqual((raised.exception.exit_code, raised.exception.outcome), (2, "blocked"))
                self.assertNotIn("https://", str(raised.exception))

    def test_uppercase_config_user_cannot_bypass_impersonation_block(self):
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home) / ".config/ludus"
            directory.mkdir(parents=True)
            (directory / "config.yaml").write_text("USER: another-user\n")
            with patch.dict(os.environ, {"HOME": home}, clear=True):
                with self.assertRaises(ludus.LudusAdapterError):
                    ludus._resolve_settings({}, ludus._load_config())

    def test_all_staged_roles_validated_before_upload_loop(self):
        deploy = function_node(workflow_tree(), "deploy")
        validations = [node for node in ast.walk(deploy) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == "validate_staged_roles"]
        self.assertEqual(len(validations), 1, "validate the full configured staged scope before any upload")
        validation = validations[0]
        self.assertEqual(ast.unparse(validation.args[0]), "staged")
        self.assertEqual(ast.unparse(validation.args[1]), "active.roles")
        upload_loop = next(node for node in ast.walk(deploy) if isinstance(node, ast.For)
                           and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                                   and call.func.attr == "upload" for call in ast.walk(node)))
        self.assertLess(validation.lineno, upload_loop.lineno)

    def test_late_terminal_observation_is_unknown(self):
        target = models.Target(models.ServerKey("server", "scope"), "range",
                               models.Capabilities("client", "server", {}, "unknown-only"))
        for status in ("success", "failure", "aborted"):
            observation = models.Observation(target, "selected", status, "user-selected", None, ())
            for remaining in (0.0, -0.01):
                with self.subTest(status=status, remaining=remaining):
                    self.assertEqual(workflow.selected_history_outcome(
                        "selected", observation, remaining_budget=remaining), "unknown")
            self.assertEqual(workflow.selected_history_outcome(
                "selected", observation, remaining_budget=0.01),
                "success" if status == "success" else "failure")

    def test_monitor_passes_post_read_budget_to_terminal_classifier(self):
        monitor = function_node(workflow_tree(), "monitor")
        classifier = next(node for node in ast.walk(monitor) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Name) and node.func.id == "selected_history_outcome")
        self.assertIn("remaining_budget", {keyword.arg for keyword in classifier.keywords})
        reads = [node.lineno for node in ast.walk(monitor) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr in {"observe_run", "observe_history"}]
        budgets = [node.lineno for node in ast.walk(monitor) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "_remaining_budget"]
        self.assertTrue(any(max(reads) < line <= classifier.lineno for line in budgets))

    def test_source_preflight_errors_are_safe_blockers(self):
        deploy = function_node(workflow_tree(), "deploy")
        handlers = [node for node in ast.walk(deploy) if isinstance(node, ast.ExceptHandler)
                    and node.type is not None and ast.unparse(node.type) == "source.SourceError"]
        self.assertEqual(len(handlers), 1)
        text = ast.unparse(handlers[0])
        self.assertIn("'blocked', 2", text)
        self.assertNotIn("str(exc)", text)

    def test_deploy_cli_contract_and_safe_help(self):
        """Parser exposes the pinned deploy defaults and help is local-only."""
        tree = cli_tree()
        source = CLI.read_text(encoding="utf-8")
        self.assertIn('"--range"', source)
        self.assertIn('required=True', source)
        self.assertIn('choices=("roles", "full")', source)
        self.assertIn('default="roles"', source)
        self.assertIn('"--checkout"', source)
        self.assertIn('"--force-upload"', source)
        self.assertIn('"reset-upload-history"', source)
        # Help is explicitly exercised by the parent test run; statically ensure
        # argparse is available without invoking the entry point on import.
        self.assertTrue(any(isinstance(node, ast.Import) and any(alias.name == "argparse" for alias in node.names)
                            for node in tree.body))
        self.assertTrue(any(isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                            and any(isinstance(part, ast.Constant) and part.value == "__main__"
                                    for part in node.test.comparators)
                            for node in tree.body), "CLI execution must be guarded on import")

    def test_monitor_cli_requires_one_explicit_selector(self):
        """Monitor supports run or selected range/history and finite positive limits."""
        tree = cli_tree()
        source = CLI.read_text(encoding="utf-8")
        self.assertIn('"--run"', source)
        self.assertIn('"--range"', source)
        self.assertIn('"--history-id"', source)
        self.assertIn('"--wait"', source)
        self.assertIn('default=10800', source)
        self.assertIn('default=30', source)
        self.assertIn("math.isfinite", source)
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "add_mutually_exclusive_group" for node in ast.walk(tree)))

    def test_monitor_has_only_read_capabilities(self):
        """Observation never deploys/uploads, edits upload ledger, or auto-attaches candidates."""
        monitor = function_node(workflow_tree(), "monitor")
        calls = [node for node in ast.walk(monitor) if isinstance(node, ast.Call)]
        attrs = {node.func.attr for node in calls if isinstance(node.func, ast.Attribute)}
        names = {node.func.id for node in calls if isinstance(node.func, ast.Name)}
        self.assertIn("discover_target", attrs)
        def attribute_path(node):
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return attribute_path(node.value) + "." + node.attr
            return ""
        read_calls = {attribute_path(call.func) for call in calls if isinstance(call.func, ast.Attribute)}
        self.assertTrue(any(path.endswith(".read.observe_run") for path in read_calls)
                        or any(path.endswith(".read.observe_history") for path in read_calls),
                        "monitor must use BoundSession.read observation methods")
        self.assertFalse(attrs & {"enable_deploy", "upload", "launch", "begin_upload", "save_entry", "reset_upload_history"})
        self.assertFalse(attrs & {"mutation_lock", "save_run"}, "monitor must not take deploy lock or rewrite source runs")
        self.assertFalse(names & {"correlate", "attach_history", "auto_attach"})
        self.assertIn("save_observation", attrs)
        self.assertIn("observation_lock", attrs)

    def test_monitor_requires_explicit_history_selection(self):
        """History mode observes the exact user-selected ID and never takes a recap shortcut."""
        monitor = function_node(workflow_tree(), "monitor")
        selected = function_node(workflow_tree(), "selected_history_outcome")
        source = ast.get_source_segment(WORKFLOW.read_text(encoding="utf-8"), monitor) or ""
        selected_source = ast.get_source_segment(WORKFLOW.read_text(encoding="utf-8"), selected) or ""
        self.assertIn("history_id", source)
        self.assertIn("observe_history", source)
        self.assertIn("selected_history_outcome", source)
        self.assertNotIn("recap", source.lower())
        self.assertIn("history_id", selected_source)
        self.assertIn("observation.history_id", selected_source)
        self.assertNotIn("candidates", selected_source)

    def test_interrupted_monitor_persists_only_observed_screened_history_id(self):
        """Keyboard interruption cannot persist the raw CLI selector as history metadata."""
        monitor = function_node(workflow_tree(), "monitor")
        interrupt = next(node for node in ast.walk(monitor) if isinstance(node, ast.ExceptHandler)
                         and isinstance(node.type, ast.Name) and node.type.id == "KeyboardInterrupt")
        source = ast.get_source_segment(WORKFLOW.read_text(encoding="utf-8"), interrupt) or ""
        self.assertIn("_persistable_history_id", source)
        self.assertNotIn("history_id if history_id else None", source)
        self.assertIsNone(workflow._persistable_history_id(None))
        target = models.Target(models.ServerKey("server", "user-scope"), "range",
                               models.Capabilities("client", "server", {}, "unknown-only"))
        safe_observation = models.Observation(target, "safe-history-1", "running", "user-selected", None, ())
        self.assertEqual(workflow._persistable_history_id(safe_observation), "safe-history-1")
        untrusted = replace(safe_observation, attribution="unknown")
        self.assertIsNone(workflow._persistable_history_id(untrusted))

    def test_monitor_deadline_budget_and_check_before_each_read(self):
        """The overall wait budget begins before discovery and no read starts after expiry."""
        self.assertEqual(workflow._remaining_budget(110.0, 100.0), 10.0)
        self.assertEqual(workflow._remaining_budget(100.0, 100.0), 0.0)
        self.assertEqual(workflow._remaining_budget(90.0, 100.0), 0.0)
        monitor = function_node(workflow_tree(), "monitor")
        calls = [node for node in ast.walk(monitor) if isinstance(node, ast.Call)]
        discovery = next(node for node in calls if isinstance(node.func, ast.Attribute)
                         and node.func.attr == "discover_target")
        observation_reads = [node for node in calls if isinstance(node.func, ast.Attribute)
                             and node.func.attr in {"observe_run", "observe_history"}]
        deadline = next(node for node in ast.walk(monitor) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "deadline" for target in node.targets))
        checks = [node for node in calls if isinstance(node.func, ast.Name)
                  and node.func.id == "_remaining_budget"]
        self.assertLess(deadline.lineno, discovery.lineno)
        self.assertTrue(observation_reads)
        self.assertTrue(checks)
        self.assertLess(min(node.lineno for node in checks), min(node.lineno for node in observation_reads))

    def test_selected_history_outcomes_require_exact_user_selection(self):
        """Only exact-ID explicit observations map terminal selected history status."""
        target = models.Target(models.ServerKey("server", "scope"), "range",
                               models.Capabilities("client", "server", {}, "unknown-only"))
        for status, expected in (("success", "success"), ("failure", "failure"), ("aborted", "failure"),
                                 ("running", "unknown"), (None, "unknown")):
            observation = models.Observation(target, "history-7", status, "user-selected", None, ())
            self.assertEqual(workflow.selected_history_outcome("history-7", observation), expected)
        mismatched = models.Observation(target, "history-other", "success", "user-selected", None, ())
        self.assertEqual(workflow.selected_history_outcome("history-7", mismatched), "unknown")
        unattributed = replace(mismatched, history_id="history-7", attribution="unknown")
        self.assertEqual(workflow.selected_history_outcome("history-7", unattributed), "unknown")

    def test_reset_has_no_remote_capability(self):
        """Reset only clears local upload history and needs no client/target/credentials."""
        reset = function_node(workflow_tree(), "reset_upload_history")
        calls = [node for node in ast.walk(reset) if isinstance(node, ast.Call)]
        attrs = {node.func.attr for node in calls if isinstance(node.func, ast.Attribute)}
        self.assertEqual(attrs & {"discover_target", "enable_deploy", "upload", "launch"}, set())
        self.assertIn("mutation_lock", attrs)
        self.assertIn("reset_upload_history", attrs)
        with tempfile.TemporaryDirectory() as directory:
            store = state.StateStore(Path(directory) / "state")
            summary = workflow.reset_upload_history(store)
            self.assertEqual(summary.invalidated_entries, 0)
            self.assertEqual(summary.exit_code, 0)

    def test_cli_report_suppresses_unverified_identifiers(self):
        """Only canonical run IDs and adapter-safe selected history IDs are displayed."""
        self.assertIsNone(ludus_deploy._safe_display_id("12345678-1234-5678-1234-567812345678", "run"))
        self.assertEqual(ludus_deploy._safe_display_id("12345678-1234-5678-1234-567812345678", "run", verified=True),
                         "12345678-1234-5678-1234-567812345678")
        self.assertIsNone(ludus_deploy._safe_display_id("not-a-run\nsecret", "run", verified=True))
        self.assertIsNone(ludus_deploy._safe_display_id("history\nsecret", "history", verified=True))
        summary = models.Summary("not-a-run\nsecret", None, "history\nsecret", "unknown", 4,
                                 "Outcome unknown", Path("/tmp/evidence"))
        output = StringIO()
        with redirect_stdout(output):
            ludus_deploy._report(summary, command="Monitor")
        self.assertNotIn("secret", output.getvalue())
        self.assertNotIn("not-a-run", output.getvalue())

    def test_cli_report_formats_verified_observation_and_candidate_guidance(self):
        """Persisted safe observations report target/attribution and distinguish history from provenance."""
        target = models.Target(models.ServerKey("safe-server", "user:test-scope"), "lab-safe",
                               models.Capabilities("client", "server", {}, "unknown-only"))
        with tempfile.TemporaryDirectory() as directory:
            store = state.StateStore(Path(directory) / "state")
            record = store.new_observation(target, None, "history-safe-9")
            record = replace(record, attribution="user-selected", outcome="success")
            with store.observation_lock(record.observation_id):
                store.save_observation(record)
            summary = models.Summary(None, record.observation_id, record.history_id, "success", 0,
                                     "Selected history record succeeded", store.evidence_dir(record.observation_id))
            verified, details = ludus_deploy._verified_report_ids(summary, store)
            output = StringIO()
            with redirect_stdout(output):
                ludus_deploy._report(summary, command="Monitor", details=details, verified_ids=verified)
        rendered = output.getvalue()
        self.assertIn("safe-server", rendered)
        self.assertIn("user:test-scope", rendered)
        self.assertIn("Attribution: user-selected", rendered)
        self.assertIn("Phase: observation", rendered)
        self.assertIn("candidate history", rendered.lower())
        self.assertIn("not launch provenance", rendered.lower())

    def test_monitor_report_explains_explicit_candidate_selection(self):
        """CLI explains how to select a candidate without claiming launch attribution."""
        summary = models.Summary(None, None, None, "unknown", 4, "Outcome remains unknown", Path("/tmp"))
        output = StringIO()
        with redirect_stdout(output):
            ludus_deploy._report(summary, command="Monitor")
        rendered = output.getvalue().lower()
        self.assertIn("monitor --range range --history-id id", rendered)
        self.assertIn("not launch provenance", rendered)

    def test_cli_handles_local_state_initialization_failure_safely(self):
        """Private-state setup failures become a fixed blocker instead of a traceback."""
        output, errors = StringIO(), StringIO()
        with patch.object(ludus_deploy, "StateStore", side_effect=OSError("credential=canary")), \
             redirect_stdout(output), redirect_stderr(errors):
            code = ludus_deploy.main(["reset-upload-history"])
        self.assertEqual(code, 2)
        self.assertNotIn("canary", output.getvalue() + errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_changed_selection(self):
        """Only exact trusted manifest/policy history plus installed presence skips upload."""
        manifest = models.Manifest(1, "digest-a", (("tasks/main.yml", "file", 0, "abc"),))
        changed = models.Manifest(1, "digest-b", (("tasks/main.yml", "file", 0, "def"),))
        role = models.ResolvedRole("alpha", Path("ansible/roles/alpha"), ())
        staged = (models.StagedRole(role, Path("/private/alpha"), manifest),)
        server = models.ServerKey("server", "user-scope")
        checkout = models.Checkout(Path("/checkout"), "rev")
        versions = ("client", "server")

        def entry(status="success", saved=manifest):
            return models.UploadEntry(server, "alpha", status, saved, "run", "now", checkout, versions, ())

        cases = (
            ({"alpha": entry(saved=changed)}, frozenset({"alpha"}), "manifest or policy changed"),
            ({"alpha": entry(saved=models.Manifest(2, manifest.digest, manifest.entries))}, frozenset({"alpha"}), "manifest or policy changed"),
            ({"alpha": entry()}, frozenset(), "missing presence"),
            ({"alpha": entry(status="unknown")}, frozenset({"alpha"}), "untrusted history"),
            ({"alpha": entry(status="in-flight")}, frozenset({"alpha"}), "untrusted history"),
            ({}, frozenset({"alpha"}), "missing history"),
        )
        for history, installed, reason in cases:
            with self.subTest(history=history, installed=installed):
                self.assertEqual(workflow.select_changed(staged, history, installed, False), {"alpha": reason})
        self.assertEqual(workflow.select_changed(staged, {"alpha": entry()}, frozenset({"alpha"}), False), {})
        self.assertEqual(workflow.select_changed(staged, {"alpha": entry()}, frozenset({"alpha"}), True), {"alpha": "forced"})

    def test_destroyed_requires_explicit_full(self):
        snapshot = models.RangeSnapshot("DESTROYED", False, False, None, None, "now")
        with self.assertRaises(models.DeploymentError) as caught:
            workflow.check_scope("roles", snapshot)
        self.assertEqual(getattr(caught.exception, "exit_code", None), 2)
        self.assertIn("Full scope required; explicitly request --scope full.", str(caught.exception))
        workflow.check_scope("full", snapshot)

    def test_scope_allows_pinned_error_and_aborted_states(self):
        for state in ("ERROR", "ABORTED"):
            with self.subTest(state=state):
                workflow.check_scope("roles", models.RangeSnapshot(state, False, False, None, None, "now"))

    def test_scope_blockers_have_precise_exit_codes(self):
        for snapshot in (
            models.RangeSnapshot("SUCCESS", True, False, None, None, "now"),
            models.RangeSnapshot("SUCCESS", False, True, None, None, "now"),
        ):
            with self.subTest(snapshot=snapshot), self.assertRaises(models.DeploymentError) as caught:
                workflow.check_scope("roles", snapshot)
            self.assertEqual(caught.exception.exit_code, 2)
        with self.assertRaises(models.DeploymentError) as caught:
            workflow.check_scope("roles", models.RangeSnapshot("UNRECOGNIZED", False, False, None, None, "now"))
        self.assertEqual(caught.exception.exit_code, 2)

    def test_launch_has_one_callsite_outside_upload_loop(self):
        tree = workflow_tree()
        deploy = function_node(tree, "deploy")
        calls = [node for node in ast.walk(deploy) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "launch"]
        self.assertEqual(len(calls), 1, "deploy must have exactly one reserved launch callsite")
        for parent in ast.walk(deploy):
            if isinstance(parent, (ast.For, ast.AsyncFor, ast.While)) and calls[0] in ast.walk(parent):
                self.fail("launch must not be inside an upload loop")
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in {"sleep", "monitor", "observe_run"} for node in ast.walk(deploy)))

    def test_preflight_precedes_upload(self):
        tree = workflow_tree()
        deploy = function_node(tree, "deploy")
        top = list(deploy.body)
        positions = {name: min((node.lineno for node in ast.walk(deploy) if isinstance(node, ast.Call)
                                and ((isinstance(node.func, ast.Name) and node.func.id == name)
                                     or (isinstance(node.func, ast.Attribute) and node.func.attr == name))),
                               default=None) for name in ("check_scope", "upload")}
        self.assertIsNotNone(positions["check_scope"])
        self.assertIsNotNone(positions["upload"])
        self.assertLess(positions["check_scope"], positions["upload"])
        self.assertFalse(any(isinstance(node, ast.Return) and isinstance(node.value, ast.Constant)
                             and node.value.value is None for node in ast.walk(deploy)),
                         "empty changed selection must not return before launch")

    def test_launch_timestamps_bracket_launch_and_acceptance_is_not_completion(self):
        deploy = function_node(workflow_tree(), "deploy")
        launch_call = next(node for node in ast.walk(deploy) if isinstance(node, ast.Call)
                           and isinstance(node.func, ast.Attribute) and node.func.attr == "launch")
        source = WORKFLOW.read_text(encoding="utf-8")
        calls = [node for node in ast.walk(deploy) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "replace"]
        start_lines = [node.lineno for node in calls if any(arg.arg == "launch_started_at" for arg in node.keywords)]
        finish_lines = [node.lineno for node in calls if any(arg.arg == "launch_finished_at" for arg in node.keywords)]
        self.assertTrue(start_lines)
        self.assertTrue(finish_lines)
        self.assertLess(max(start_lines), launch_call.lineno)
        self.assertGreater(min(finish_lines), launch_call.lineno)
        self.assertIn('phase="launched"', source)
        self.assertIn('outcome="accepted"', source)
        self.assertNotIn('phase="complete", outcome="accepted"', source)

    def test_launch_result_is_classified_before_first_post_launch_write(self):
        """Each mutually-exclusive disposition is classified before its own writes."""
        deploy = function_node(workflow_tree(), "deploy")
        launch_call = next(node for node in ast.walk(deploy) if isinstance(node, ast.Call)
                           and isinstance(node.func, ast.Attribute) and node.func.attr == "launch")
        launch_statement = next(node for node in ast.walk(deploy) if isinstance(node, ast.Assign)
                                and launch_call in ast.walk(node))

        def containing_sequence(parent):
            for _field, value in ast.iter_fields(parent):
                if isinstance(value, list):
                    if launch_statement in value:
                        return value
                    for item in value:
                        if isinstance(item, ast.AST):
                            found = containing_sequence(item)
                            if found is not None:
                                return found
                elif isinstance(value, ast.AST):
                    found = containing_sequence(value)
                    if found is not None:
                        return found
            return None

        statements = containing_sequence(deploy)
        self.assertIsNotNone(statements, "launch must be in an inspectable statement sequence")
        launch_index = statements.index(launch_statement)
        decisions = [node for node in statements[launch_index + 1:]
                     if isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                     and isinstance(node.test.left, ast.Attribute)
                     and node.test.left.attr == "accepted"]
        self.assertEqual(len(decisions), 2, "accepted and rejected launch results need explicit branches")
        first_decision_index = statements.index(min(decisions, key=lambda item: item.lineno))

        def disposition_branch(value):
            return next(node for node in decisions if node.test.comparators
                        and isinstance(node.test.comparators[0], ast.Constant)
                        and node.test.comparators[0].value is value)

        def calls_in(node, names):
            return [call for call in ast.walk(node) if isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name) and call.func.id in names]

        self.assertFalse(any(calls_in(statement, {"_persist", "_durable_write"})
                             for statement in statements[launch_index + 1:first_decision_index]),
                         "do not write an unresolved launch response before branching")

        for disposition, branch_value in (("launched", True), ("launch-rejected", False)):
            branch = disposition_branch(branch_value)
            matching = [call for call in calls_in(branch, {"replace"})
                        if {key.arg: key.value.value for key in call.keywords
                            if key.arg in {"phase", "outcome"} and isinstance(key.value, ast.Constant)}
                        == {"phase": disposition,
                            "outcome": "accepted" if branch_value else "failure"}]
            writes = calls_in(branch, {"_persist", "_durable_write"})
            self.assertTrue(matching, f"{disposition} needs an in-memory transition")
            self.assertTrue(writes, f"{disposition} must be recorded")
            self.assertLess(min(call.lineno for call in matching), min(call.lineno for call in writes))

        unknown = next((call for call in calls_in(deploy, {"replace"})
                        if {keyword.arg: keyword.value.value for keyword in call.keywords
                            if keyword.arg in {"phase", "outcome"} and isinstance(keyword.value, ast.Constant)}
                        == {"phase": "launch-unknown", "outcome": "unknown"}), None)
        self.assertIsNotNone(unknown, "ambiguous launch needs an in-memory transition")
        later_writes = [call for call in calls_in(deploy, {"_persist", "_durable_write"})
                        if call.lineno > unknown.lineno]
        self.assertTrue(later_writes, "ambiguous launch must be recorded after classification")
        self.assertEqual(disposition_branch(False).lineno < unknown.lineno, True,
                         "ambiguous response must be classified after the explicit rejection check")

    def test_upload_reservation_does_not_claim_verified_identity(self):
        deploy = function_node(workflow_tree(), "deploy")
        source = ast.get_source_segment(WORKFLOW.read_text(encoding="utf-8"), deploy) or ""
        self.assertIn('None, checkout, (session.target.capabilities.client_version,', source)
        self.assertIn('identity_evidence=("user-scoped installed-role presence",)', source)
        self.assertIn('outcome="failure"', source)
        self.assertIn("if launch.accepted is False:", source)
        self.assertIn("source.manifest(item.directory)", source)
        self.assertNotIn("source.manifest(item.role.source)", source)

    def test_mutation_lock_contention_returns_blocker_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            store = state.StateStore(Path(directory) / "state")
            with store.mutation_lock():
                summary = workflow.deploy("range", "roles", None, False, store)
            self.assertEqual(summary.exit_code, 2)
            self.assertEqual(summary.outcome, "blocked")

    def test_known_launch_acceptance_survives_later_exception_transition(self):
        target = models.Target(
            models.ServerKey("server", "scope"), "range",
            models.Capabilities("client", "server", {}, "unknown-only"),
        )
        checkout = models.Checkout(Path("/checkout"), "revision")
        accepted = models.RunRecord(
            "run-id", target, "roles", checkout, "digest", "launched", 0, 1,
            None, (), "started", "finished", None, "accepted",
        )
        transition = getattr(workflow, "failure_transition", None)
        self.assertIsNotNone(transition, "workflow must expose a pure exception transition")
        result = transition(accepted, "unknown")
        self.assertEqual(result.outcome, "accepted")
        self.assertEqual(result.phase, "launched")
        self.assertEqual(result.launch_started_at, "started")
        self.assertEqual(result.launch_finished_at, "finished")
        self.assertEqual(accepted.outcome, "accepted", "transition must not mutate the original record")

    def test_exception_paths_apply_and_persist_failure_transition(self):
        deploy = function_node(workflow_tree(), "deploy")
        handlers = [node for node in ast.walk(deploy) if isinstance(node, ast.ExceptHandler)]
        generic = next((handler for handler in handlers
                        if isinstance(handler.type, ast.Name) and handler.type.id == "Exception"), None)
        self.assertIsNotNone(generic)
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "_exception_summary" for node in ast.walk(generic)),
                        "caught exceptions must use safe terminal reporting")
        terminal = function_node(workflow_tree(), "_exception_summary")
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "failure_transition" for node in ast.walk(terminal)),
                        "caught exceptions must transition run state")
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "_persist" for node in ast.walk(terminal)),
                        "failure transition must be durably recorded when possible")

    def test_configured_identity_validation_precedes_resolution_and_persistence(self):
        tree = workflow_tree()
        deploy = function_node(tree, "deploy")
        calls = [node for node in ast.walk(deploy) if isinstance(node, ast.Call)]
        validation = next((node for node in calls if isinstance(node.func, ast.Attribute)
                           and node.func.attr == "validate_configured_roles"), None)
        self.assertIsNotNone(validation, "bound session must screen configured identities against secrets")
        resolve = next(node for node in calls if isinstance(node.func, ast.Attribute)
                       and node.func.attr == "resolve_roles")
        persist = next(node for node in calls if isinstance(node.func, ast.Attribute)
                       and node.func.attr == "new_run")
        self.assertLess(validation.lineno, resolve.lineno)
        self.assertLess(validation.lineno, persist.lineno)
        session = class_node(adapter_tree(), "BoundSession")
        self.assertTrue(any(isinstance(node, ast.FunctionDef) and node.name == "validate_configured_roles"
                            for node in session.body))

    def test_adapter_command_shapes_match_research(self):
        """Require literal argv construction matching the pinned CLI contract."""
        tree = adapter_tree()
        expected = {
            "_client_version_argv": ("ludus", "version"),
            "_server_version_argv": ("ludus", "version", "--verbose"),
            "_active_config_argv": ("ludus", "range", "config", "get", "--range", "<range>", "--json"),
            "_status_argv": ("ludus", "range", "status", "--range", "<range>", "--json"),
            "_installed_roles_argv": ("ludus", "ansible", "role", "list", "--range", "<range>", "--json"),
            "_history_list_argv": ("ludus", "range", "logs", "--history", "--range", "<range>", "--json"),
            "_upload_argv": ("ludus", "ansible", "role", "add", "--directory", "<stage>", "--force", "--json"),
            "_launch_roles_argv": ("ludus", "range", "deploy", "--range", "<range>", "--tags", "user-defined-roles", "--json"),
            "_launch_full_argv": ("ludus", "range", "deploy", "--range", "<range>", "--json"),
        }
        found: dict[str, tuple[str, ...]] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in expected:
                values = []
                for item in ast.walk(node):
                    if isinstance(item, (ast.List, ast.Tuple)):
                        literals = [elt.value for elt in item.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
                        if literals:
                            values.append(tuple(literals))
                found[node.name] = max(values, key=len, default=())
        self.assertEqual(set(found), set(expected), "adapter must expose all documented pure argv builders")
        self.assertEqual(found, expected)

    def test_read_client_has_no_mutation_entrypoint(self):
        """Read capability has only documented reads; deploy requires explicit opt-in."""
        tree = adapter_tree()
        read_client = class_node(tree, "_ReadClient")
        methods = {
            node.name
            for node in read_client.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertTrue({"active_config", "status", "installed_roles", "history_list", "observe_history", "observe_run"} <= methods)
        self.assertFalse({"upload", "launch", "deploy", "install", "mutate"} & methods)
        deploy_client = class_node(tree, "DeployClient")
        deploy_methods = {
            node.name
            for node in deploy_client.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertTrue({"upload", "launch"} <= deploy_methods)
        self.assertTrue(any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "enable_deploy"
            for node in tree.body
        ), "mutation capability must be explicitly enabled")

    def test_version_parser_uses_independent_pinned_labels(self):
        """Parse client and verbose server labels, not any matching version token."""
        client, server = ludus._parse_versions(
            "INFO Ludus client 2.3.10+fccf931e\nAnsible version: 1.26.3\n",
            "\x1b[32mINFO\x1b[0m Ludus Server 2.3.10+fccf931e - licensed to example\n",
        )
        self.assertEqual(client, "2.3.10+fccf931e")
        self.assertEqual(server, "2.3.10+fccf931e")
        for text in (
            "INFO Ludus Server 2.3.10+fccf931e - text\nINFO Ludus Server 2.3.11+abcdef12 - text",
            "INFO unrelated component 2.3.10+fccf931e",
        ):
            with self.assertRaises(ludus.LudusAdapterError):
                ludus._parse_versions("INFO Ludus client 2.3.10+fccf931e", text)
        with self.assertRaises(ludus.LudusAdapterError):
            ludus._parse_versions(
                "INFO Ludus client 2.3.10+fccf931e",
                "INFO Ludus Server 2.3.11+abcdef12 - licensed",
            )
        for client_line in (
            "INFO Ludus client 2.3.10+fccf931e-extra",
            "INFO Ludus client 2.3.10+fccf931e.other",
        ):
            with self.subTest(client=client_line), self.assertRaises(ludus.LudusAdapterError):
                ludus._parse_versions(
                    client_line,
                    "INFO Ludus Server 2.3.10+fccf931e - licensed",
                )
        with self.assertRaises(ludus.LudusAdapterError):
            ludus._parse_versions(
                "INFO Ludus client 2.3.11+abcdef12",
                "INFO Ludus Server 2.3.10+fccf931e - licensed",
            )

    def test_settings_defaults_and_environment_precedence_are_pinned(self):
        """Resolve documented URL/TLS defaults and treat empty environment as unset."""
        resolve = ludus._resolve_settings
        self.assertEqual(
            resolve({}, {}),
            ("https://198.51.100.1:8080", "", False),
        )
        self.assertEqual(
            resolve({"LUDUS_URL": "", "LUDUS_PROXY": "", "LUDUS_VERIFY": ""},
                    {"url": "https://configured.invalid:8080", "proxy": "http://proxy.invalid", "verify": True}),
            ("https://configured.invalid:8080", "http://proxy.invalid", True),
        )
        self.assertEqual(
            resolve({"LUDUS_URL": "https://env.invalid:8080", "LUDUS_VERIFY": "false"},
                    {"url": "https://configured.invalid:8080", "verify": True}),
            ("https://env.invalid:8080", "", False),
        )
        with self.assertRaises(ludus.LudusAdapterError):
            resolve({"LUDUS_USER": "other"}, {"user": "other"})
        for malformed in ({"url": False}, {"proxy": []}):
            with self.subTest(config=malformed), self.assertRaises(ludus.LudusAdapterError):
                resolve({}, malformed)

    def test_range_id_rejects_cli_query_and_flag_injection(self):
        """Range IDs are validated before being passed to the CLI's query argument."""
        for bad in ("x&userID=ROOT", "x?foo=1", "x#frag", "x/y", "x=y", "--help", "x%26y"):
            with self.subTest(value=bad), self.assertRaises(ludus.LudusAdapterError):
                ludus._validate_range_id(bad)
        self.assertEqual(ludus._validate_range_id("lab-01"), "lab-01")

    def test_capture_path_is_bounded_without_disk_or_preexec(self):
        """Capture must be bounded while draining both pipes; never spill raw output to disk."""
        capture = next(node for node in adapter_tree().body if isinstance(node, ast.FunctionDef) and node.name == "_capture_process")
        source = source_segment(capture)
        self.assertNotIn("tempfile", source)
        self.assertNotIn("preexec_fn", source)
        self.assertNotIn("communicate(", source)
        self.assertIn("selectors", source)
        self.assertIn("PIPE", source)
        self.assertEqual(sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr == "Popen" for node in ast.walk(capture)), 1)

    def test_mutation_operation_timeouts_are_fixed_and_bounded(self):
        """Source policies bound potentially slow mutation commands separately from reads."""
        source = source_segment(class_node(adapter_tree(), "DeployClient"))
        self.assertIn("timeout=300", source)
        self.assertIn("timeout=120", source)

    def test_local_child_capture_is_bounded_and_closes_inherited_pipes(self):
        """Exercise only the local capture primitive, never Ludus or server behavior."""
        result = ludus._capture_process(
            (sys.executable, "-c", "import sys; sys.stdout.write('o'*8192); sys.stderr.write('e'*8192)"),
            timeout=3,
            max_output=1024,
            env={},
        )
        self.assertEqual(len(result.stdout.encode()), 1024)
        self.assertEqual(len(result.stderr.encode()), 1024)
        self.assertTrue(result.truncated)

        command = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)']); "
            "time.sleep(3)"
        )
        result = ludus._capture_process((sys.executable, "-c", command), timeout=0.2, max_output=1024, env={})
        self.assertTrue(result.timed_out)

    def test_capture_cleanup_is_bounded_and_handles_base_exception(self):
        """Static contract requires whole-process-group cleanup and bounded waits."""
        tree = adapter_tree()
        node = next((item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_capture_process"), None)
        self.assertIsNotNone(node, "process capture must be independently testable with local child processes")
        source = source_segment(node)
        self.assertIn("BaseException", source)
        self.assertIn("killpg", source)
        self.assertIn("timeout", source)
        for call in (item for item in ast.walk(node) if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == "wait"):
            self.assertTrue(any(keyword.arg == "timeout" for keyword in call.keywords), "process wait must be bounded")

    def test_secret_registry_only_collects_sensitive_values_and_rejects_cycles(self):
        """Ordinary labels cannot poison metadata filters; cyclic YAML fails closed."""
        config = {
            "a": "ordinary-value",
            "password": "pw-canary",
            "nested": {"api_key": "key-canary", "client_secret": "secret-canary"},
        }
        self.assertEqual(
            ludus._collect_sensitive_values(config),
            frozenset({"pw-canary", "key-canary", "secret-canary"}),
        )
        cyclic = {}
        cyclic["nested"] = cyclic
        with self.assertRaises(ludus.LudusAdapterError):
            ludus._collect_sensitive_values(cyclic)

    def test_history_id_validator_screens_selected_id_against_secrets(self):
        """User-selected IDs cannot bypass the same secret filter used for listed IDs."""
        self.assertIsNone(ludus._safe_history_id("run-secret-12", ("secret",)))
        self.assertEqual(ludus._safe_history_id("run-123", ("secret",)), "run-123")

    def test_only_exact_authorization_error_wrapper_is_a_definitive_denial(self):
        """Extra fields and non-string error values remain ambiguous, never failures."""
        denial = "You are not authorized to perform this ansible action"
        result = ludus._classify_upload_response({"error": denial})
        self.assertEqual(result.disposition, "failure")
        for value in (
            {"error": denial, "debug": "extra"},
            {"error": [denial]},
            ["error", denial],
        ):
            with self.subTest(value=value):
                result = ludus._classify_upload_response(value)
                self.assertEqual(result.disposition, "unknown")

    def test_bound_session_cannot_be_retargeted_by_target_reassignment(self):
        """Deployment capability must remain anchored to the discovered target."""
        node = class_node(adapter_tree(), "BoundSession")
        frozen = any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "dataclass"
            and any(keyword.arg == "frozen" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    for keyword in decorator.keywords)
            for decorator in node.decorator_list
        )
        target_property = any(
            isinstance(item, ast.FunctionDef) and item.name == "target"
            and any(isinstance(decorator, ast.Name) and decorator.id == "property" for decorator in item.decorator_list)
            for item in node.body
        )
        self.assertTrue(frozen or target_property, "BoundSession.target must be immutable")
        deploy_factory = next(node for node in adapter_tree().body if isinstance(node, ast.FunctionDef) and node.name == "enable_deploy")
        self.assertIn("session.target", source_segment(deploy_factory))

    def test_upload_error_branch_type_checks_before_message_lookup(self):
        """An arbitrary JSON top-level value cannot crash classification via .get()."""
        source = source_segment(class_node(adapter_tree(), "DeployClient"))
        self.assertIn("isinstance(value, dict)", source)
        self.assertIn("Role upload outcome is unknown", source)

    def test_unknown_range_states_are_not_accepted_as_known(self):
        """State decoding recognizes only the pinned contract's explicit state set."""
        allowed = {"DEPLOYING", "DESTROYING", "ERROR", "ABORTED", "DESTROYED", "NEVER DEPLOYED", "SUCCESS"}
        for state in allowed:
            self.assertEqual(ludus._validate_range_state(state), state)
        for state in ("", "UNKNOWN", "SUCCESS ", "success", "DESTROYING\x00"):
            with self.subTest(state=state), self.assertRaises(ludus.LudusAdapterError):
                ludus._validate_range_state(state)

    def test_sensitive_metadata_is_suppressed_not_relayed(self):
        """Secret-bearing, control-bearing, or overlong values cannot enter public metadata."""
        safe = ludus._safe_metadata_text
        self.assertIsNone(safe("token=canary-123", ("canary-123",)))
        self.assertIsNone(safe("line\nnext", ()))
        self.assertIsNone(safe("x" * 4097, ()))
        self.assertEqual(safe("SUCCESS", ("canary-123",)), "SUCCESS")

    def test_secret_registry_populates_before_config_and_upload_data_boundary(self):
        """Config and staged defaults are registered before data reaches output handling."""
        reader = source_segment(class_node(adapter_tree(), "_ReadClient"))
        deploy = source_segment(class_node(adapter_tree(), "DeployClient"))
        active = reader[reader.index("def active_config"):reader.index("def status")]
        upload = deploy[deploy.index("def upload"):deploy.index("def launch")]
        self.assertLess(active.index("_register_config_secrets"), active.index("return value"))
        self.assertLess(upload.index("_register_role_secrets"), upload.index("_execute"))


if __name__ == "__main__":
    unittest.main()
