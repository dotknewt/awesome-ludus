"""Durable local state contract checks; these tests never contact Ludus."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from scripts.ludus_deployment import models, source
except ModuleNotFoundError as exc:
    if exc.name not in {"scripts.ludus_deployment", "scripts.ludus_deployment.models", "scripts.ludus_deployment.source"}:
        raise
    models = SimpleNamespace(__name__="scripts.ludus_deployment.models")
    source = SimpleNamespace(__name__="scripts.ludus_deployment.source")

try:
    from scripts.ludus_deployment import state
except ModuleNotFoundError as exc:
    if exc.name not in {"scripts.ludus_deployment", "scripts.ludus_deployment.state"}:
        raise
    state = SimpleNamespace(__name__="scripts.ludus_deployment.state")


def api(module, name):
    value = getattr(module, name, None)
    if value is None:
        raise AssertionError(f"required production API {module.__name__}.{name} is missing")
    return value


class LudusStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "state"
        api(state, "StateStore")
        api(models, "ServerKey")
        api(models, "Capabilities")
        self.store = state.StateStore(self.root)
        self.checkout = models.Checkout(Path(self.temp.name), "revision")
        self.caps = models.Capabilities("client", "server", {}, "unknown-only")
        self.server_a = models.ServerKey("https://one.invalid", "token-a")
        self.server_b = models.ServerKey("https://two.invalid", "token-a")
        self.target_a = models.Target(self.server_a, "range-a", self.caps)

    def tearDown(self):
        self.temp.cleanup()

    def upload(self, server=None, role="web", status="success", run_id="run-1"):
        return models.UploadEntry(
            server=server or self.server_a,
            role=role,
            status=status,
            manifest=None,
            run_id=run_id,
            uploaded_at="2026-10-23T00:00:00Z" if status == "success" else None,
            checkout=self.checkout,
            versions=("client", "server"),
            identity_evidence=("user-selected",),
        )

    def test_private_paths_and_symlink_rejection(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload())
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        records = list(self.root.rglob("*.json"))
        self.assertTrue(records, "a durable JSON state record should exist")
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in records))

        alias = Path(self.temp.name) / "state-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            state.StateStore(alias)
        for unsafe in ("../escape", "/absolute", "", "a/b"):
            with self.subTest(unsafe=unsafe), self.assertRaises((ValueError, OSError)):
                self.store.stage_root(unsafe)

    def observe_real_fsync(self, events):
        actual_fsync = os.fsync

        def observed(fd):
            info = os.fstat(fd)
            path = Path(os.readlink(f"/proc/self/fd/{fd}"))
            actual_fsync(fd)
            events.append(("directory" if stat.S_ISDIR(info.st_mode) else "file", path))

        return patch.object(state.os, "fsync", side_effect=observed)

    def test_new_state_root_ancestors_are_durably_linked(self):
        events = []
        base = Path(self.temp.name)
        root = base / "new-parent" / "nested" / "state"
        with self.observe_real_fsync(events):
            state.StateStore(root)
        parents = [base, base / "new-parent", root.parent]
        positions = []
        for parent in parents:
            self.assertIn(("directory", parent), events)
            positions.append(events.index(("directory", parent)))
        self.assertEqual(positions, sorted(positions))

    def test_first_upload_reservation_syncs_new_directory_before_record(self):
        events = []
        with self.observe_real_fsync(events), self.store.mutation_lock():
            self.store.begin_upload(self.upload(status="in-flight"))
        self.assertIn(("directory", self.root), events)
        file_sync = next(index for index, (kind, path) in enumerate(events)
                         if kind == "file" and path.parent == self.root / "uploads")
        self.assertLess(events.index(("directory", self.root)), file_sync)
        self.assertIn(("directory", self.root / "uploads"), events[file_sync + 1:])
        self.assertEqual(self.store.load_entry(self.server_a, "web").status, "unknown")

    def test_run_and_observation_directories_sync_each_new_parent(self):
        events = []
        with self.observe_real_fsync(events):
            run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
            observation = self.store.new_observation(self.target_a, None, None)
        for parent in (self.root, self.root / "stages", self.root / "evidence"):
            self.assertIn(("directory", parent), events)
        self.assertTrue(self.store.stage_root(run.run_id).is_dir())
        self.assertTrue(self.store.evidence_dir(observation.observation_id).is_dir())

    def test_new_journal_syncs_file_then_parent_before_return(self):
        run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
        events = []
        with self.store.run_lock(run.run_id), self.observe_real_fsync(events):
            self.store.write_event(run.run_id, {"type": "phase", "phase": "preflight"})
        parent = self.store.evidence_dir(run.run_id)
        self.assertIn(("file", parent / "events.jsonl"), events)
        self.assertIn(("directory", parent), events)
        self.assertLess(events.index(("file", parent / "events.jsonl")),
                        events.index(("directory", parent)))
        self.assertEqual(json.loads((parent / "events.jsonl").read_text())["phase"], "preflight")

    def test_scope_partition_and_lock_domain(self):
        # A key includes both server identity and access scope; endpoint alone
        # (or credential scope alone) must not alias another user's cache.
        other_scope = models.ServerKey(self.server_a.identity, "token-b")
        other_endpoint = models.ServerKey(self.server_b.identity, self.server_a.access_scope)
        with self.store.mutation_lock():
            self.store.save_entry(self.upload(self.server_a, "web"))
            self.store.save_entry(self.upload(other_scope, "web"))
            self.store.save_entry(self.upload(other_endpoint, "web"))
        reopened = state.StateStore(self.root)
        self.assertIsNotNone(reopened.load_entry(self.server_a, "web"))
        self.assertIsNotNone(reopened.load_entry(other_scope, "web"))
        self.assertIsNotNone(reopened.load_entry(other_endpoint, "web"))
        self.assertIsNone(reopened.load_entry(self.server_a, "db"))

    def test_real_process_lock_contention(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload())
        code = r'''\
import sys
from pathlib import Path
from scripts.ludus_deployment.state import StateStore
store = StateStore(Path(sys.argv[1]))
with store.mutation_lock():
    print("LOCKED", flush=True)
    sys.stdin.readline()
'''
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2]) + os.pathsep + env.get("PYTHONPATH", "")
        child = subprocess.Popen(
            [sys.executable, "-c", code, str(self.root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")
            started = time.monotonic()
            with self.assertRaises(RuntimeError):
                with state.StateStore(self.root).mutation_lock():
                    self.fail("contended mutation lock unexpectedly acquired")
            self.assertLess(time.monotonic() - started, 0.3)
            child.stdin.write("release\n")
            child.stdin.flush()
            child.communicate(timeout=5)
            with state.StateStore(self.root).mutation_lock():
                pass
        finally:
            if child.poll() is None:
                child.stdin.write("release\n")
                child.stdin.flush()
                child.communicate(timeout=5)

    def test_inflight_is_unknown_after_reopen(self):
        with self.store.mutation_lock():
            self.store.begin_upload(self.upload(status="in-flight"))
        recovered = state.StateStore(self.root).load_entry(self.server_a, "web")
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.status, "unknown")

    def test_atomic_record_preserves_confirmed_entries(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload(role="web"))
            self.store.save_entry(self.upload(role="db"))
        with self.store.mutation_lock():
            self.store.save_entry(self.upload(role="db", run_id="run-2"))
        reopened = state.StateStore(self.root)
        self.assertEqual(reopened.load_entry(self.server_a, "web").run_id, "run-1")
        self.assertEqual(reopened.load_entry(self.server_a, "db").run_id, "run-2")
        self.assertFalse(list(self.root.rglob("*.tmp")), "temporary replacement files must be cleaned up")

    def test_corrupt_state_blocks(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload())
        record = next(self.root.rglob("*.json"))
        record.write_text("{not valid JSON", encoding="utf-8")
        reopened = state.StateStore(self.root)
        with self.assertRaises((ValueError, OSError)):
            reopened.load_entry(self.server_a, "web")
        # Corruption cannot be silently interpreted as a cache miss.
        with self.assertRaises((ValueError, OSError)):
            with reopened.mutation_lock():
                reopened.begin_upload(self.upload(status="in-flight"))

    def test_begin_upload_invalidates_other_keys_for_exact_role_before_reservation(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload(self.server_a, "web"))
            self.store.save_entry(self.upload(self.server_b, "web"))
            self.store.save_entry(self.upload(self.server_b, "db"))
        with self.store.mutation_lock():
            self.store.begin_upload(self.upload(self.server_a, "web", "in-flight", "run-2"))
        reopened = state.StateStore(self.root)
        self.assertEqual(reopened.load_entry(self.server_a, "web").status, "unknown")
        self.assertEqual(reopened.load_entry(self.server_b, "web").status, "unknown")
        self.assertEqual(reopened.load_entry(self.server_b, "db").status, "success")
        self.assertEqual(reopened.load_entry(self.server_a, "web").run_id, "run-2")

    def test_begin_upload_requires_global_lock(self):
        with self.assertRaises((RuntimeError, ValueError)):
            self.store.begin_upload(self.upload(status="in-flight"))

    def test_reset_invalidates_upload_history_and_preserves_evidence(self):
        with self.store.mutation_lock():
            run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
            self.store.save_run(run)
            observation = self.store.new_observation(self.target_a, run.run_id, None)
            with self.store.observation_lock(observation.observation_id):
                self.store.save_observation(observation)
            self.store.save_entry(self.upload(role="web"))
            self.store.save_entry(self.upload(role="db"))
        with self.store.mutation_lock():
            self.assertEqual(self.store.reset_upload_history(), 2)
        reopened = state.StateStore(self.root)
        self.assertIsNone(reopened.load_entry(self.server_a, "web"))
        self.assertIsNone(reopened.load_entry(self.server_a, "db"))
        self.assertEqual(reopened.load_run(run.run_id), run)
        self.assertTrue(self.store.evidence_dir(run.run_id).exists())
        self.assertTrue(self.store.evidence_dir(observation.observation_id).exists())

    def test_reset_requires_global_lock(self):
        with self.assertRaises((RuntimeError, ValueError)):
            self.store.reset_upload_history()

    def test_shared_lock_contention_across_endpoint_and_user_keys(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload())
        code = r'''\
import sys
from pathlib import Path
from scripts.ludus_deployment.state import StateStore
store = StateStore(Path(sys.argv[1]))
with store.mutation_lock():
    print("LOCKED", flush=True)
    sys.stdin.readline()
'''
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2]) + os.pathsep + env.get("PYTHONPATH", "")
        child = subprocess.Popen([sys.executable, "-c", code, str(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True, env=env)
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")
            started = time.monotonic()
            with self.assertRaises(RuntimeError):
                with state.StateStore(self.root).mutation_lock():
                    self.fail("contended mutation lock unexpectedly acquired")
            self.assertLess(time.monotonic() - started, 0.3)
            child.stdin.write("release\n")
            child.stdin.flush()
            child.communicate(timeout=5)
            with state.StateStore(self.root).mutation_lock():
                pass
        finally:
            if child.poll() is None:
                child.stdin.write("release\n")
                child.stdin.flush()
                child.communicate(timeout=5)

    def test_sanitizes_exception_and_output_canaries(self):
        sanitize = api(state, "sanitize")
        secrets = frozenset({"CANARY_TOKEN_123", "CANARY_PASSWORD_456"})
        hostile = (
            "request failed token=CANARY_TOKEN_123 "
            "https://alice:CANARY_PASSWORD_456@example.invalid/api?token=CANARY_TOKEN_123 "
            "password=CANARY_PASSWORD_456"
        )
        safe = sanitize(hostile, secrets)
        self.assertNotIn("CANARY_TOKEN_123", safe)
        self.assertNotIn("CANARY_PASSWORD_456", safe)
        self.assertNotIn("alice:", safe)
        self.assertNotIn("https://", safe)
        self.assertNotIn("token=", safe.lower())
        huge = "CANARY_TOKEN_123" + "x" * (70 * 1024)
        bounded = sanitize(huge, secrets)
        self.assertNotIn("CANARY_TOKEN_123", bounded)
        self.assertLessEqual(len(bounded.encode("utf-8")), 64 * 1024)

    def test_write_event_never_persists_unsafe_payload_or_nested_sensitive_fields(self):
        with self.store.mutation_lock():
            run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
            self.store.save_run(run)
        canaries = ("CANARY_STDOUT_789", "CANARY_ERROR_321", "CANARY_URL_SECRET_654", "CANARY_NESTED_987")
        event = {
            "type": "diagnostic",
            "message": f"exception: {canaries[1]}",
            "stdout": canaries[0],
            "url": f"https://name:{canaries[2]}@example.invalid/?access_token={canaries[2]}",
            "details": {"password": canaries[3], "arbitrary": "untrusted payload"},
        }
        with self.store.run_lock(run.run_id):
            self.store.write_event(run.run_id, event)
        persisted = b"".join(path.read_bytes() for path in self.store.evidence_dir(run.run_id).rglob("*") if path.is_file())
        for canary in canaries:
            self.assertNotIn(canary.encode(), persisted)
        self.assertNotIn(b"untrusted payload", persisted)
        decoded = [json.loads(line) for line in persisted.splitlines() if line.strip()]
        self.assertTrue(decoded, "an explicit safe event or suppression marker should be persisted")

    def test_nonempty_source_manifest_roundtrips_through_upload_record(self):
        from dataclasses import replace

        role = self.root.parent / "role"
        role.mkdir()
        (role / "payload.txt").write_text("actual source bytes\n", encoding="utf-8")
        manifest = source.manifest(role)
        self.assertTrue(manifest.entries)
        entry = replace(self.upload(), manifest=manifest)
        with self.store.mutation_lock():
            self.store.save_entry(entry)
        restored = self.store.load_entry(self.server_a, "web")
        self.assertEqual(restored.manifest, manifest)

    def test_typed_state_rejects_wrong_shapes_and_tuple_arity(self):
        from dataclasses import replace

        manifest = models.Manifest(1, "a" * 64, (("file", "b" * 64, 12, "100644"),))
        with self.store.mutation_lock():
            self.store.save_entry(replace(self.upload(), manifest=manifest))
        record = next(self.root.joinpath("uploads").glob("*.json"))
        baseline = json.loads(record.read_text(encoding="utf-8"))
        corruptions = (
            lambda raw: raw["payload"].update(manifest=123),
            lambda raw: raw["payload"].update(checkout=123),
            lambda raw: raw["payload"]["checkout"].update(root="/tmp/not-a-path-tag"),
            lambda raw: raw["payload"].update(versions={"__tuple__": ["only-one"]}),
            lambda raw: raw["payload"].update(versions="client,server"),
        )
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt):
                broken = json.loads(json.dumps(baseline))
                corrupt(broken)
                record.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises((TypeError, ValueError)):
                    self.store.load_entry(self.server_a, "web")
        record.write_text(json.dumps(baseline), encoding="utf-8")

        run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
        with self.store.mutation_lock():
            self.store.save_run(run)
        run_path = self.root / "runs" / f"{run.run_id}.json"
        stored_run = json.loads(run_path.read_text(encoding="utf-8"))
        for bad_mapping in (123, "not-a-mapping", {"vm": 42}):
            with self.subTest(identity_rules=bad_mapping):
                broken = json.loads(json.dumps(stored_run))
                broken["payload"]["target"]["capabilities"]["identity_rules"] = bad_mapping
                run_path.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises((TypeError, ValueError)):
                    self.store.load_run(run.run_id)

    def test_global_mutation_lock_fails_promptly_on_real_process_contention(self):
        code = r'''\
import sys, time
from pathlib import Path
from scripts.ludus_deployment.state import StateStore
with StateStore(Path(sys.argv[1])).mutation_lock():
    print("LOCKED", flush=True)
    time.sleep(1.0)
'''
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2]) + os.pathsep + env.get("PYTHONPATH", "")
        child = subprocess.Popen([sys.executable, "-c", code, str(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        result = []
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")

            def attempt():
                try:
                    with state.StateStore(self.root).mutation_lock():
                        result.append("acquired")
                except (BlockingIOError, RuntimeError):
                    result.append("blocked")

            waiter = threading.Thread(target=attempt)
            started = time.monotonic()
            waiter.start()
            waiter.join(timeout=0.3)
            self.assertFalse(waiter.is_alive(), "contended lock acquisition should fail rather than block")
            self.assertEqual(result, ["blocked"])
            self.assertLess(time.monotonic() - started, 0.3)
        finally:
            child.communicate(timeout=5)

    def test_observation_lock_allows_independent_save_during_global_mutation(self):
        with self.store.mutation_lock():
            observation = self.store.new_observation(self.target_a, None, None)
        outcome = []

        def save_observation():
            try:
                with self.store.observation_lock(observation.observation_id):
                    self.store.save_observation(observation)
                outcome.append("saved")
            except Exception as exc:  # captured for assertion in main thread
                outcome.append(exc)

        with self.store.mutation_lock():
            worker = threading.Thread(target=save_observation)
            worker.start()
            worker.join(timeout=0.5)
            self.assertFalse(worker.is_alive(), "observation writes must not acquire the global mutation lock")
        self.assertEqual(outcome, ["saved"])
        self.assertEqual(self.store._record_path("observations", observation.observation_id).stat().st_mode & 0o777, 0o600)

    def test_private_intermediate_directories_and_upload_directory_are_validated(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload())
            self.store.new_run(self.target_a, "roles", self.checkout, "digest")
        directories = [path for path in self.root.rglob("*") if path.is_dir()]
        self.assertTrue(directories)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in directories))
        uploads = self.root / "uploads"
        uploads.chmod(0o755)
        with self.assertRaises((ValueError, OSError)):
            self.store.load_entry(self.server_a, "web")

    def test_begin_and_reset_validate_payload_and_key_before_mutating(self):
        with self.store.mutation_lock():
            self.store.save_entry(self.upload(role="web"))
        path = next((self.root / "uploads").glob("*.json"))
        original = json.loads(path.read_text(encoding="utf-8"))
        malformed = json.loads(json.dumps(original))
        malformed["payload"]["versions"] = {"__tuple__": ["one"]}
        corrupted_bytes = json.dumps(malformed).encode("utf-8")
        path.write_bytes(corrupted_bytes)
        with self.store.mutation_lock(), self.assertRaises((TypeError, ValueError)):
            self.store.begin_upload(self.upload(role="web", status="in-flight", run_id="next"))
        self.assertEqual(path.read_bytes(), corrupted_bytes, "failed invalidation must not rewrite corrupt records")
        with self.store.mutation_lock(), self.assertRaises((TypeError, ValueError)):
            self.store.reset_upload_history()
        self.assertTrue(path.exists(), "invalid record must not be deleted by reset")
        self.assertEqual(path.read_bytes(), corrupted_bytes)

        wrong_key = json.loads(json.dumps(original))
        wrong_key["key"] = "f" * 64
        path.write_text(json.dumps(wrong_key), encoding="utf-8")
        with self.store.mutation_lock(), self.assertRaises((TypeError, ValueError)):
            self.store.begin_upload(self.upload(role="web", status="in-flight", run_id="next"))
        wrong_key_bytes = json.dumps(wrong_key).encode("utf-8")
        with self.store.mutation_lock(), self.assertRaises((TypeError, ValueError)):
            self.store.reset_upload_history()
        self.assertEqual(path.read_bytes(), wrong_key_bytes, "reset must preserve records with mismatched key digests")

    def test_sanitizer_redacts_secrets_crossing_limit_and_unknown_bearer(self):
        secret = "CANARY_SECRET_CROSSES_BOUNDARY"
        text = "x" * (64 * 1024 - 5) + secret
        safe = state.sanitize(text, frozenset({secret}))
        self.assertNotIn("CANARY", safe)
        bearer = state.sanitize("Authorization: Bearer CANARY_UNKNOWN_BEARER", frozenset())
        self.assertNotIn("CANARY_UNKNOWN_BEARER", bearer)

    def test_event_type_canary_suppressed_and_journal_keeps_safe_outcomes_and_marker(self):
        with self.store.mutation_lock():
            run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
            self.store.save_run(run)
            self.store.save_entry(self.upload(role="web", run_id=run.run_id))
            self.store.save_entry(self.upload(role="db", run_id=run.run_id))
        with self.store.run_lock(run.run_id):
            self.store.write_event(run.run_id, {"type": "CANARY_TYPE_987", "role": "web", "disposition": "confirmed"})
            self.store.write_event(run.run_id, {"type": "upload", "role": "CANARY_ROLE_123", "phase": "CANARY_PHASE_456", "disposition": "success"})
            self.store.write_event(run.run_id, {"type": "upload", "role": "db", "disposition": "unknown"})
            self.store.write_event(run.run_id, {"type": "phase", "role": "web", "phase": "upload", "disposition": "confirmed"})
            for phase in ("staged", "uploading", "verified", "launch-reserved", "launch-unknown"):
                self.store.write_event(run.run_id, {"type": "phase", "role": "web", "phase": phase, "disposition": "unknown"})
        journal = self.store.evidence_dir(run.run_id) / "events.jsonl"
        content = journal.read_text(encoding="utf-8")
        self.assertNotIn("CANARY_TYPE_987", content)
        self.assertNotIn("CANARY_ROLE_123", content)
        self.assertNotIn("CANARY_PHASE_456", content)
        self.assertIn('"role":"web"', content)
        self.assertIn('"disposition":"confirmed"', content)
        self.assertIn('"role":"db"', content)
        self.assertIn('"disposition":"unknown"', content)
        self.assertIn('"phase":"upload"', content)
        for phase in ("staged", "uploading", "verified", "launch-reserved", "launch-unknown"):
            self.assertIn(f'"phase":"{phase}"', content)

        valid_prior = json.dumps(
            {"type": "outcome", "disposition": "success", "role": "r" * 120},
            sort_keys=True,
            separators=(",", ":"),
        ).encode() + b"\n"
        with self.store.mutation_lock():
            self.store.save_entry(self.upload(role="r" * 120, run_id=run.run_id))
        fill_count = (10 * 1024 * 1024 - 256) // len(valid_prior)
        journal.write_bytes(valid_prior * fill_count)
        with self.store.run_lock(run.run_id):
            for _ in range(20):
                self.store.write_event(run.run_id, {"type": "upload", "role": "web", "disposition": "success"})
        persisted = journal.read_bytes()
        records = [json.loads(line) for line in persisted.splitlines()]
        markers = [index for index, record in enumerate(records) if record.get("type") == "truncated"]
        self.assertLessEqual(len(persisted), 10 * 1024 * 1024)
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0], len(records) - 1, "truncation marker must remain the final complete JSONL record")
        self.assertTrue(all(record.get("type") == "outcome" for record in records[:fill_count]))

    def test_unknown_inflight_upload_role_is_trusted_only_for_its_run_and_target(self):
        with self.store.mutation_lock():
            run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
            self.store.save_run(run)
            self.store.begin_upload(self.upload(role="recovery_role", status="in-flight", run_id=run.run_id))
            self.store.save_entry(self.upload(role="unrelated_role", status="success", run_id="another-run"))
            self.store.save_entry(self.upload(server=self.server_b, role="other_target_role", status="success", run_id=run.run_id))
        recovered = self.store.load_entry(self.server_a, "recovery_role")
        self.assertEqual(recovered.status, "unknown")
        with self.store.run_lock(run.run_id):
            self.store.write_event(run.run_id, {"type": "outcome", "role": "recovery_role", "disposition": "unknown"})
            self.store.write_event(run.run_id, {"type": "outcome", "role": "unrelated_role", "disposition": "failure"})
            self.store.write_event(run.run_id, {"type": "outcome", "role": "other_target_role", "disposition": "failure"})
            self.store.write_event(run.run_id, {"type": "outcome", "role": "CANARY_UNKNOWN_ROLE", "disposition": "unknown"})
        content = (self.store.evidence_dir(run.run_id) / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"role":"recovery_role"', content)
        self.assertIn('"disposition":"unknown"', content)
        self.assertNotIn("unrelated_role", content)
        self.assertNotIn("other_target_role", content)
        self.assertNotIn("CANARY_UNKNOWN_ROLE", content)

    def test_observation_lock_cannot_authorize_stage_cleanup(self):
        with self.store.mutation_lock():
            run = self.store.new_run(self.target_a, "roles", self.checkout, "digest")
            observation = self.store.new_observation(self.target_a, None, None)
        with self.store.observation_lock(run.run_id), self.assertRaises(RuntimeError):
            self.store.cleanup_stage(run.run_id)

    def test_xdg_state_namespace_is_project_scoped(self):
        from unittest.mock import patch

        with patch.dict(os.environ, {"XDG_STATE_HOME": str(Path(self.temp.name) / "xdg")}):
            xdg_store = state.StateStore()
        self.assertEqual(xdg_store.root, Path(self.temp.name) / "xdg" / "awesome-ludus")


if __name__ == "__main__":
    unittest.main()
