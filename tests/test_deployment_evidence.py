import ast
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deployment_evidence as de
import deployment_evidence_profiles as profiles

SHARED_TASK = "splunk_container_logs : Publish the sanitized shared HEC input diagnostic report"
KUBE_TASK = "splunk_container_logs : Publish the sanitized Kubernetes input diagnostic report"
HELM_TASK = "splunk_container_logs : Publish only the safe Helm failure report"
VALID_TASKS = [SHARED_TASK, KUBE_TASK, HELM_TASK]


def status(state="SUCCESS", deployment="2026-10-25T11:03:55.13Z", range_id="r1"):
    return {"rangeID": range_id, "lastDeployment": deployment, "rangeState": state, "private": "STATUS-CANARY"}


def names_from_action_plugin():
    source = (ROOT / "ansible/roles/splunk_container_logs/action_plugins/splunk_container_logs_input_diagnostics.py").read_text()
    tree = ast.parse(source)
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"CONDITION_CATALOGUE", "KUBERNETES_CONDITION_CATALOGUE", "TYPE_VARIABLES", "KUBERNETES_TYPE_VARIABLES", "TYPE_CODES", "EVALUATION_ERROR"}:
                value = ast.literal_eval(node.value)
                result[name] = [row[0] for row in value] if "CATALOGUE" in name else value
    return result


def valid_input_report(kubernetes=False):
    catalogue = "kubernetes" if kubernetes else "shared"
    names = profiles.PREDICATES[catalogue]
    types = profiles.TYPE_VARIABLES[catalogue]
    return {"predicates": [{"name": n, "result": True} for n in names],
            "input_types": [{"name": n, "type": "text"} for n in types]}


def valid_helm_report():
    return {
        "failure_context": "available",
        "classification": {name: False for name in profiles.HELM_CLASSIFICATIONS},
        "metadata": {"fqcn": "kubernetes.core.helm", "provenance": "post_failure_loader_snapshot",
                     "collections_context": "failed_task_collections", "status": "available",
                     "module_path": "/trusted/kubernetes/core/plugins/modules/helm.py",
                     "module_realpath": "/trusted/kubernetes/core/plugins/modules/helm.py",
                     "version": "5.2.0", "sha256": "a" * 64},
    }


def task_log(task, *results):
    return f"TASK [{task}] ********************************************************\n" + "\n".join(results) + "\n"


def recap(host, **overrides):
    counts = {"ok": 0, "changed": 0, "unreachable": 0, "failed": 0,
              "skipped": 0, "rescued": 0, "ignored": 0}
    counts.update(overrides)
    return f"{host} : " + " ".join(f"{key}={value}" for key, value in counts.items()) + "\n"


class ParserTests(unittest.TestCase):
    def collect(self, log, allow=None, st=None):
        return de.collect_evidence(io.StringIO(log), st or status(), allow or {"hosts": ["host1", "host2"], "tasks": VALID_TASKS}, range_id="r1", deployment="2026-10-25T11:03:55.13Z")

    def test_real_prefixed_task_and_multiple_host_results_are_separate(self):
        result = self.collect(task_log("splunk_container_logs : Probe inputs", "ok: [host1] => {\"changed\": false}", "changed: [host2] => {\"changed\": true}"), {"hosts": ["host1", "host2"], "tasks": ["splunk_container_logs : Probe inputs"]})
        self.assertEqual([(x["host"], x["outcome"]) for x in result["tasks"]], [("host1", "ok"), ("host2", "changed")])
        self.assertEqual([x["occurrence"] for x in result["tasks"]], [1, 1])

    def test_repeated_task_headings_and_published_reports_keep_occurrences(self):
        report = json.dumps({"msg": valid_input_report()})
        log = task_log(SHARED_TASK, "ok: [host1] => " + report)
        log += task_log(SHARED_TASK, "ok: [host1] => " + report)
        result = self.collect(log, {"hosts": ["host1"], "tasks": [SHARED_TASK]})
        self.assertEqual([row["occurrence"] for row in result["tasks"]], [1, 2])
        self.assertEqual([row["occurrence"] for row in result["reports"]], [1, 2])

    def test_actual_fatal_and_unreachable_forms_and_unknown_result(self):
        log = task_log("splunk_container_logs : Probe", "fatal: [host1]: FAILED! => {\"msg\": \"secret\"}", "unreachable: [host2]: UNREACHABLE! => {\"msg\": \"secret\"}")
        result = self.collect(log, {"hosts": ["host1", "host2"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertEqual([x["outcome"] for x in result["tasks"]], ["failed", "unreachable"])
        self.assertNotIn("secret", json.dumps(result))
        unknown = self.collect(task_log("splunk_container_logs : Probe", "mystery: [host1] => {}"), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("unsupported_callback", unknown["issues"])
        self.assertEqual(unknown["tasks"][0]["outcome"], "unknown")

    def test_reports_require_prefixed_allowed_task_and_host_and_keep_identity(self):
        report = valid_input_report()
        payload = json.dumps({"msg": report}, indent=2)
        log = task_log(SHARED_TASK, "ok: [host1] => " + payload)
        result = self.collect(log, {"hosts": ["host1"], "tasks": [SHARED_TASK]})
        self.assertEqual(result["reports"][0]["report"], report)
        self.assertEqual((result["reports"][0]["occurrence"], result["reports"][0]["host"]), (1, "host1"))
        denied = self.collect(log, {"hosts": ["other"], "tasks": [SHARED_TASK]})
        self.assertEqual(denied["reports"], [])
        self.assertNotIn("host1", json.dumps(denied))

    def test_all_three_production_reports_validate_and_schema_rows_are_exact(self):
        for task, report, profile in ((SHARED_TASK, valid_input_report(), "shared_input"),
                                      (KUBE_TASK, valid_input_report(True), "kubernetes_input"),
                                      (HELM_TASK, valid_helm_report(), "helm")):
            with self.subTest(profile=profile):
                log = task_log(task, "ok: [host1] => " + json.dumps({"msg": report}))
                result = self.collect(log, {"hosts": ["host1"], "tasks": [task]})
                self.assertEqual(result["reports"][0]["profile"], profile)
                self.assertEqual(result["reports"][0]["report"], report)

    def test_catalogues_are_static_ast_agreements_with_role_source(self):
        actual = names_from_action_plugin()
        self.assertEqual(actual["CONDITION_CATALOGUE"], list(profiles.PREDICATES["shared"]))
        self.assertEqual(actual["KUBERNETES_CONDITION_CATALOGUE"], list(profiles.PREDICATES["kubernetes"]))
        self.assertEqual(list(actual["TYPE_VARIABLES"]), list(profiles.TYPE_VARIABLES["shared"]))
        self.assertEqual(list(actual["KUBERNETES_TYPE_VARIABLES"]), list(profiles.TYPE_VARIABLES["kubernetes"]))
        self.assertEqual(set(actual["TYPE_CODES"].values()) | {actual["EVALUATION_ERROR"], "other"}, profiles.TYPE_CODES)
        helm_source = (ROOT / "ansible/roles/splunk_container_logs/action_plugins/splunk_container_logs_helm_diagnostics.py").read_text()
        helm_ast = ast.parse(helm_source)
        constants = {node.targets[0].id: ast.literal_eval(node.value) for node in helm_ast.body
                     if isinstance(node, ast.Assign) and len(node.targets) == 1
                     and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id in {"CLASSIFICATION_KEYS", "FQCN", "PROVENANCE"}}
        self.assertEqual(tuple(constants["CLASSIFICATION_KEYS"]), profiles.HELM_CLASSIFICATIONS)
        self.assertEqual(constants["FQCN"], "kubernetes.core.helm")
        self.assertEqual(constants["PROVENANCE"], "post_failure_loader_snapshot")
        task_sources = [ROOT / "ansible/roles/splunk_container_logs/tasks/preflight.yml",
                        ROOT / "ansible/roles/splunk_container_logs/tasks/kubernetes/input.yml",
                        ROOT / "ansible/roles/splunk_container_logs/tasks/kubernetes/helm.yml"]
        source_text = "\n".join(path.read_text() for path in task_sources)
        for profile_task in profiles.PROFILE_TASKS.values():
            self.assertIn(profile_task.split(" : ", 1)[1], source_text)

    def test_invalid_rows_duplicates_unknown_identifiers_and_metadata_types_reject(self):
        report = valid_input_report()
        report["predicates"][0]["name"] = "IDENTIFIER-CANARY"
        self.assertIsNone(profiles.validate("shared_input", report))
        report = valid_input_report(); report["predicates"].append(report["predicates"][0])
        self.assertIsNone(profiles.validate("shared_input", report))
        report = valid_helm_report(); report["metadata"]["collections_context"] = []
        self.assertIsNone(profiles.validate("helm", report))
        report = valid_helm_report()
        report["failure_context"] = "failure_context_unavailable"
        report["metadata"] = {"fqcn": "kubernetes.core.helm", "provenance": "post_failure_loader_snapshot",
                              "collections_context": "collection_context_unavailable", "status": "unresolved"}
        self.assertEqual(profiles.validate("helm", report), report)
        self.assertIsNone(profiles.validate("shared_input", {"predicates": [], "input_types": []}))

    def test_duplicate_json_nonfinite_and_malformed_report_are_issues(self):
        for payload in ('{"msg":{"a":1,"a":2}}', '{"msg":{"x":NaN}}', '{"msg": [}'):
            result = self.collect(task_log(SHARED_TASK, "ok: [host1] => " + payload), {"hosts": ["host1"], "tasks": [SHARED_TASK]})
            self.assertIn("malformed_report", result["issues"])

    def test_missing_publication_payload_is_incomplete(self):
        result = self.collect(task_log(SHARED_TASK, "ok: [host1] => {\"changed\": false}"), {"hosts": ["host1"], "tasks": [SHARED_TASK]})
        self.assertIn("report_missing", result["issues"])
        self.assertEqual(result["reports"], [])

    def test_empty_garbage_missing_result_and_missing_recap_are_incomplete(self):
        for log in ("", "garbage\n", task_log("splunk_container_logs : Probe")):
            result = self.collect(log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
            self.assertTrue(result["issues"])
            self.assertIn("unknown", [row["outcome"] for row in result["tasks"]] or ["unknown"])

    def test_missing_and_duplicate_recaps_and_status_contradiction_are_incomplete(self):
        result = self.collect(task_log("splunk_container_logs : Probe", "fatal: [host1]: FAILED! => {}") + "PLAY RECAP ***\n" + recap("host1", failed=1) + recap("host1", failed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_duplicate", result["issues"])
        self.assertIn("status_contradiction", result["issues"])
        missing = self.collect("garbage", {"hosts": ["host1"], "tasks": []})
        self.assertIn("recap_missing", missing["issues"])

    def test_recaps_require_schema_coverage_and_per_host_lower_bounds(self):
        changed = task_log("splunk_container_logs : Probe", "changed: [host1] => {}")
        result = self.collect(changed + "PLAY RECAP ***\n" + recap("host1", changed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_mismatch", result["issues"])

        valid_changed = self.collect(changed + "PLAY RECAP ***\n" + recap("host1", ok=1, changed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertNotIn("recap_mismatch", valid_changed["issues"])

        missing_host = task_log("splunk_container_logs : Probe", "ok: [host1] => {}", "changed: [host2] => {}")
        result = self.collect(missing_host + "PLAY RECAP ***\n" + recap("host1", ok=1), {"hosts": ["host1", "host2"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_coverage_missing", result["issues"])

        incomplete = self.collect("PLAY RECAP ***\nhost1 : ok=1\n", {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_invalid", incomplete["issues"])

        repeated = task_log("splunk_container_logs : Probe", "changed: [host1] => {}")
        repeated += task_log("splunk_container_logs : Probe", "changed: [host1] => {}")
        result = self.collect(repeated + "PLAY RECAP ***\n" + recap("host1", changed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_mismatch", result["issues"])

        valid_repeated = self.collect(repeated + "PLAY RECAP ***\n" + recap("host1", ok=2, changed=2), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertNotIn("recap_mismatch", valid_repeated["issues"])

        ok_then_changed = task_log("splunk_container_logs : Probe", "ok: [host1] => {}")
        ok_then_changed += task_log("splunk_container_logs : Probe", "changed: [host1] => {}")
        result = self.collect(ok_then_changed + "PLAY RECAP ***\n" + recap("host1", ok=2, changed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertNotIn("recap_mismatch", result["issues"])

    def test_mixed_item_success_outcomes_have_conservative_recap_lower_bounds(self):
        items = task_log("splunk_container_logs : Probe",
                         "ok: [host1] => (item=first) => {}",
                         "skipping: [host1] => (item=second) => {\"skipped\": true}")
        result = self.collect(items + "PLAY RECAP ***\n" + recap("host1", ok=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertNotIn("recap_mismatch", result["issues"])

    def test_item_results_count_once_and_filtered_events_are_not_issues(self):
        items = task_log("splunk_container_logs : Probe",
                         "changed: [host1] => (item=first) => {}",
                         "changed: [host1] => (item=second) => {}")
        result = self.collect(items + "PLAY RECAP ***\n" + recap("host1", changed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_mismatch", result["issues"])
        result = self.collect(items + "PLAY RECAP ***\n" + recap("host1", ok=1, changed=1), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertNotIn("recap_mismatch", result["issues"])

        full_log = task_log("other_role : Other task", "changed: [other-host] => {}")
        full_log += task_log("splunk_container_logs : Probe", "changed: [host1] => {}")
        full_log += "PLAY RECAP ***\n" + recap("host1", ok=1, changed=1) + recap("other-host", ok=8, changed=8)
        selected = self.collect(full_log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertEqual(selected["issues"], [])
        self.assertEqual([row["name"] for row in selected["tasks"]], ["splunk_container_logs : Probe"])

        excluded_host = task_log("splunk_container_logs : Probe", "changed: [other-host] => {}")
        excluded_host += "PLAY RECAP ***\n" + recap("host1") + recap("other-host", changed=1)
        selected = self.collect(excluded_host, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertEqual(selected["issues"], [])
        self.assertEqual(selected["tasks"], [])

        recap_only = self.collect("PLAY RECAP ***\n" + recap("host1", ok=2), {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertEqual(recap_only["issues"], [])
        self.assertEqual(recap_only["tasks"], [])

    def test_rescued_or_ignored_failures_do_not_create_false_success_contradictions(self):
        for counter in ({"rescued": 1}, {"ignored": 1}):
            log = task_log("splunk_container_logs : Probe", "fatal: [host1]: FAILED! => {}")
            log += "PLAY RECAP ***\n" + recap("host1", ok=1, **counter)
            result = self.collect(log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
            self.assertEqual(result["tasks"][0]["outcome"], "failed")
            self.assertNotIn("status_contradiction", result["issues"])
            self.assertNotIn("recap_mismatch", result["issues"])

        ignored_then_unreachable = task_log("splunk_container_logs : Probe", "fatal: [host1]: FAILED! => {}")
        ignored_then_unreachable += task_log("splunk_container_logs : Probe", "unreachable: [host1]: UNREACHABLE! => {}")
        ignored_then_unreachable += "PLAY RECAP ***\n" + recap("host1", ok=1, unreachable=1, ignored=1)
        result = self.collect(ignored_then_unreachable, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("status_contradiction", result["issues"])

        unaccounted = task_log("splunk_container_logs : Probe", "fatal: [host1]: FAILED! => {}")
        unaccounted += "PLAY RECAP ***\n" + recap("host1")
        result = self.collect(unaccounted, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("recap_mismatch", result["issues"])

    def test_optional_publication_skip_does_not_require_report(self):
        for event in ("skipping: [host1]", 'skipping: [host1] => {"skipped": true}'):
            log = task_log(HELM_TASK, event) + "PLAY RECAP ***\n" + recap("host1", skipped=1)
            result = self.collect(log, {"hosts": ["host1"], "tasks": [HELM_TASK]})
            self.assertEqual(result["tasks"][0]["outcome"], "skipped")
            self.assertNotIn("report_missing", result["issues"])
            self.assertEqual(result["reports"], [])

    def test_malformed_generic_payload_and_framing_are_reported(self):
        for payload in ("{BROKEN}", "{"):
            log = task_log("splunk_container_logs : Probe", "ok: [host1] => " + payload)
            log += "PLAY RECAP ***\n" + recap("host1", ok=1)
            result = self.collect(log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
            self.assertIn("malformed_payload", result["issues"])

    def test_identity_mismatch_is_preserved_as_unverified_not_combined(self):
        result = self.collect("", st=status(range_id="different"))
        self.assertEqual(result["expected"]["range"], "r1")
        self.assertEqual(result["observed"]["range"], "different")
        self.assertIn("identity_mismatch", result["issues"])
        self.assertIn("unverified", result["attribution"])
        timestamp = self.collect("", st=status(deployment="2026-10-25T11:03:56.13Z"))
        self.assertEqual(timestamp["observed"]["deployment"], "2026-10-25T11:03:56.13Z")
        self.assertIn("identity_mismatch", timestamp["issues"])

    def test_timestamp_calendar_validation_and_fractional_seconds(self):
        self.assertEqual(self.collect("", st=status())["observed"]["deployment"], "2026-10-25T11:03:55.13Z")
        with self.assertRaises(de.EvidenceError):
            self.collect("", st=status(deployment="2026-99-99T88:00:00Z"))
        with self.assertRaises(de.EvidenceError):
            self.collect("", st=status(state="deployed"))
        with self.assertRaises(de.EvidenceError):
            self.collect("", st=status(state="RUNNING"))
        self.assertEqual(self.collect("", st=status(state="DEPLOYING"))["deployment_state"], "DEPLOYING")

    def test_stream_exception_is_replaced_with_fixed_error(self):
        class BadStream:
            def read(self, _size):
                raise RuntimeError("STREAM-CANARY")
        with self.assertRaises(de.EvidenceError) as caught:
            de.collect_evidence(BadStream(), status(), {"hosts": ["host1"], "tasks": []},
                                range_id="r1", deployment="2026-10-25T11:03:55.13Z")
        self.assertEqual(str(caught.exception), "invalid input")
        self.assertNotIn("CANARY", str(caught.exception))

    def test_raw_canaries_never_escape_and_inner_payload_lines_are_not_events(self):
        log = task_log(SHARED_TASK, "ok: [host1] => {", '  "msg": {"predicates": [], "input_types": []},', "TASK [CANARY] ***", "}")
        result = self.collect(log, {"hosts": ["host1"], "tasks": [SHARED_TASK]})
        encoded = json.dumps(result)
        self.assertNotIn("CANARY", encoded)
        self.assertEqual(len(result["tasks"]), 1)
        self.assertEqual(result["tasks"][0]["name"], SHARED_TASK)

    def test_untrusted_callback_payload_cannot_inject_allowlisted_task_heading(self):
        log = task_log("private : unreviewed", "ok: [evil] => {", "TASK [splunk_container_logs : Probe] ***", "}")
        result = self.collect(log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertEqual(result["tasks"], [])
        self.assertNotIn("Probe", json.dumps(result))

    def test_untrusted_task_host_message_and_invalid_metadata_canaries_are_removed(self):
        helm = valid_helm_report()
        helm["metadata"]["module_path"] = "/CANARY : invalid/kubernetes/core/plugins/modules/helm.py"
        log = task_log("CANARY-UNTRUSTED-TASK", "fatal: [CANARY-HOST]: FAILED! => {\"msg\": \"CANARY-MESSAGE\"}")
        log += task_log(HELM_TASK, "ok: [host1] => " + json.dumps({"msg": helm}))
        result = self.collect(log, {"hosts": ["host1"], "tasks": [HELM_TASK]})
        encoded = json.dumps(result)
        for canary in ("CANARY-UNTRUSTED-TASK", "CANARY-HOST", "CANARY-MESSAGE", "CANARY : invalid"):
            self.assertNotIn(canary, encoded)
        self.assertIn("malformed_report", result["issues"])

    def test_delegation_uses_only_bracket_identity_and_requires_both_allowlisted(self):
        log = task_log("splunk_container_logs : delegated", "ok: [host1 -> host2] => {\"changed\": false}")
        result = self.collect(log, {"hosts": ["host1", "host2"], "tasks": ["splunk_container_logs : delegated"]})
        self.assertEqual(result["tasks"][0]["delegated_host"], "host2")
        denied = self.collect(log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : delegated"]})
        self.assertEqual(denied["tasks"], [])
        self.assertNotIn("host2", json.dumps(denied))

    def test_conflicting_repeated_host_outcome_is_issue_and_recap_is_not_exactly_compared(self):
        log = task_log("splunk_container_logs : Probe", "ok: [host1] => {}", "fatal: [host1]: FAILED! => {}")
        log += "PLAY RECAP ***\n" + recap("host1", ok=99)
        result = self.collect(log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertIn("task_contradiction", result["issues"])
        self.assertIn("recap_mismatch", result["issues"])
        self.assertNotIn("status_contradiction", result["issues"])
        success_log = task_log("splunk_container_logs : Probe", "ok: [host1] => {}")
        success_log += "PLAY RECAP ***\n" + recap("host1", ok=99)
        success = self.collect(success_log, {"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]})
        self.assertNotIn("status_contradiction", success["issues"])

    def test_oversized_multiline_report_is_bounded_and_incomplete(self):
        lines = ["x" * 15_000 for _ in range(de.MAX_BLOCK // 15_000 + 2)]
        log = task_log(SHARED_TASK, "ok: [host1] => {\"msg\": {") + "\n".join(lines)
        result = self.collect(log, {"hosts": ["host1"], "tasks": [SHARED_TASK]})
        self.assertIn("input_truncated", result["issues"])
        self.assertEqual(result["reports"], [])


class CliTests(unittest.TestCase):
    def command_for(self, td, output="out", state="SUCCESS"):
        root = Path(td)
        status_file = root / "status.json"
        allow_file = root / "allow.json"
        status_file.write_text(json.dumps(status(state=state)))
        allow_file.write_text(json.dumps({"hosts": ["host1"], "tasks": ["splunk_container_logs : Probe"]}))
        command = [sys.executable, str(ROOT / "scripts/collect_deployment_evidence.py"), "--range", "r1", "--deployment", "2026-10-25T11:03:55.13Z", "--status", str(status_file), "--allowlist", str(allow_file), "--output", str(root / output)]
        return command, root / output

    def invoke(self, td, output="out", log="", state="SUCCESS"):
        command, destination = self.command_for(td, output, state)
        return subprocess.run(command, input=log, text=True, capture_output=True), destination, command

    def test_private_modes_incomplete_exit_and_output_collision(self):
        with tempfile.TemporaryDirectory() as td:
            result, output, command = self.invoke(td, log=task_log("splunk_container_logs : Probe", "ok: [host1] => {}") + "PLAY RECAP ***\n" + recap("host1", ok=1))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "evidence.json").stat().st_mode & 0o777, 0o600)
            collision = subprocess.run(command, input="", text=True, capture_output=True)
            self.assertEqual(collision.returncode, 2)
            self.assertNotIn("complete", collision.stdout)

    def test_unknown_argument_canary_is_not_echoed_and_symlink_output_refused(self):
        with tempfile.TemporaryDirectory() as td:
            result, _, command = self.invoke(td)
            bad = subprocess.run(command + ["--CANARY-ARG"], text=True, capture_output=True)
            self.assertNotIn("CANARY", bad.stdout + bad.stderr)
            target = Path(td) / "target"; target.mkdir()
            link = Path(td) / "link"; link.symlink_to(target, target_is_directory=True)
            linked = subprocess.run(command[:-1] + [str(link / "new")], input="", text=True, capture_output=True)
            self.assertEqual(linked.returncode, 2)
            self.assertFalse((target / "new").exists())

    def test_malformed_json_canary_not_echoed_and_failed_capture_is_not_deployment_success(self):
        with tempfile.TemporaryDirectory() as td:
            result, _, command = self.invoke(td)
            (Path(td) / "status.json").write_text('{"rangeID":"r1","lastDeployment":"x","rangeState":"ERROR","secret":"CANARY","secret":"x"}')
            bad = subprocess.run(command, input="CANARY", text=True, capture_output=True)
            self.assertEqual(bad.returncode, 2)
            self.assertNotIn("CANARY", bad.stdout + bad.stderr)

    def test_failed_deployment_can_be_captured_successfully_and_status_private_fields_drop(self):
        with tempfile.TemporaryDirectory() as td:
            log = task_log("splunk_container_logs : Probe", "fatal: [host1]: FAILED! => {}") + "PLAY RECAP ***\n" + recap("host1", failed=1)
            result, output, _ = self.invoke(td, log=log, state="ERROR")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((output / "evidence.json").read_text())
            self.assertEqual(report["deployment_state"], "ERROR")
            self.assertNotIn("private", report)

    def test_incomplete_capture_exit_three_and_input_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            result, _, _ = self.invoke(td, log="TASK [splunk_container_logs : Probe] ***\n")
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout.strip(), "capture: incomplete")
        with tempfile.TemporaryDirectory() as td:
            command, _ = self.command_for(td)
            status_path = Path(td, "status.json")
            real = Path(td, "actual.json"); real.write_text(status_path.read_text())
            status_path.unlink(); status_path.symlink_to(real)
            failed = subprocess.run(command, input="", text=True, capture_output=True)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stderr.strip(), "capture: error")

    def test_oversized_local_json_read_is_bounded_and_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as td:
            command, output = self.command_for(td)
            Path(td, "status.json").write_text(" " * (256_001))
            failed = subprocess.run(command, input="", text=True, capture_output=True)
            self.assertEqual(failed.returncode, 2)
            self.assertFalse(output.exists())
            self.assertNotIn(" ", failed.stderr.replace("capture: error", ""))

    def test_missing_argument_errors_do_not_echo_caller_values(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/collect_deployment_evidence.py"), "--range", "CANARY"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("CANARY", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
