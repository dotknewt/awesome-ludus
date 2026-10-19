"""Stateful privileged-operation model for stock log access tests.

The production helper and modeled recreation/rotation operate on the private
pytest tree.  This adapter supplies unavailable privileged facts and keeps them
bound to the real test files' physical inode transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys


@dataclass(frozen=True)
class Identity:
    name: str
    uid: int
    gid: int


@dataclass(frozen=True)
class FileFacts:
    uid: int = 0
    gid: int = 4
    mode: int = 0o640
    nlink: int = 1
    dev: int = 1
    ino: int = 1
    regular: bool = True
    symlink: bool = False
    extended_acl: bool = False
    trusted_parents: bool = True


@dataclass(frozen=True)
class ProducerObservation:
    active: bool | None
    identity_valid: bool
    pid: int = 410
    start_identity: str = "410:9001"


class InjectedFailure(OSError):
    def __init__(self, message: str) -> None:
        super().__init__(5, message)


class ModelHost:
    """Strict state-derived host implementing the helper's private host protocol."""

    def __init__(self, root: Path, reader: str = "splunkfwd") -> None:
        self.root = root
        self.reader = reader
        gid = 2201 if reader == "splunkfwd" else 2202
        self.users = {reader: Identity(reader, gid, gid)}
        self.groups = {
            reader: Identity(reader, gid, gid),
            "root": Identity("root", 0, 0),
            "adm": Identity("adm", 4, 4),
        }
        self.packages = {"rsyslog", "logrotate"}
        self.files: dict[str, FileFacts] = {}
        self.producer = ProducerObservation(True, True)
        self.configured_argv = ["/usr/sbin/rsyslogd", "-n", "-iNONE"]
        self.running_argv = list(self.configured_argv)
        self.running_executable = "/usr/sbin/rsyslogd"
        self.drop_ins: list[str] = []
        self.root_directory = ""
        self.root_image = ""
        self.mount_matches = True
        self.command_records = 1
        self.command_record_recognized = True
        self.observation_error = False
        self.observation_transition = False
        self.observation_sequence: list[ProducerObservation] = []
        self.validator_available = True
        self.validator_accepts = True
        self.restart_result = True
        self.restart_observation: bool | None = True
        self.consumer_running = True
        self.operations: list[str] = []
        self.failures: dict[tuple[str, str], int] = {}
        self.callbacks: dict[tuple[str, str], object] = {}
        self.state_uid_overrides: dict[str, int] = {}
        self.group_close_error_for: str | None = None
        self.loaded_action_groups: dict[str, int] = {}
        self.physical_inodes: dict[str, int] = {}
        self.primitive_faults: dict[str, int] = {}
        self.rotation_profile_hashes: dict[str, str] = {}

    def add_file(self, path: str, *, gid: int = 4, ino: int | None = None, mode: int = 0o640) -> None:
        if ino is None:
            ino = 100 + len(self.files)
        self.files[path] = FileFacts(gid=gid, ino=ino, mode=mode)
        physical = self.root / path.lstrip("/")
        if physical.is_file():
            self.physical_inodes[path] = physical.stat().st_ino

    def fail_once(self, operation: str, when: str = "before") -> None:
        self.failures[(operation, when)] = self.failures.get((operation, when), 0) + 1

    def capture_rotation_profile(self, profile_dir: Path) -> None:
        bundles = {
            "/etc/logrotate.conf": "logrotate.conf",
            "/etc/logrotate.d/rsyslog": "rsyslog.logrotate",
            "/usr/lib/rsyslog/rsyslog-rotate": "rsyslog-rotate",
        }
        self.rotation_profile_hashes = {
            logical: hashlib.sha256((profile_dir / bundle).read_bytes()).hexdigest()
            for logical, bundle in bundles.items()
        }

    def checkpoint(self, operation: str, when: str) -> None:
        key = (operation, when)
        callback = self.callbacks.pop(key, None)
        if callback is not None:
            callback()
        if self.failures.get(key, 0):
            self.failures[key] -= 1
            raise InjectedFailure(f"injected {when} {operation}")

    def package_installed(self, package: str, _command: str) -> bool:
        return package in self.packages

    def state_uid(self, logical_path: str, _actual_uid: int) -> int:
        return self.state_uid_overrides.get(logical_path, 0)

    def lookup_user(self, name: str, _command: str) -> Identity | None:
        return self.users.get(name)

    def lookup_group(self, name: str, _command: str) -> Identity | None:
        return self.groups.get(name)

    def file_facts(self, logical_path: str, _physical_path: Path) -> FileFacts | None:
        return self.files.get(logical_path)

    def set_group(self, logical_path: str, physical_path: Path, gid: int, expected: FileFacts) -> None:
        facts = self.files.get(logical_path)
        if facts is None or facts != expected or not physical_path.is_file():
            raise InjectedFailure("set_group on missing file")
        self.operations.append(f"group:{logical_path}:{gid}")
        self.files[logical_path] = replace(facts, gid=gid)
        if self.group_close_error_for == logical_path:
            raise OSError(5, "injected close after group mutation")

    def after_publish(self, logical_path: str, physical_path: Path) -> None:
        if not physical_path.is_file():
            raise InjectedFailure("publication did not create a regular file")
        old = self.files[logical_path]
        self.files[logical_path] = replace(old, ino=old.ino + 1000)
        self.physical_inodes[logical_path] = physical_path.stat().st_ino
        self.operations.append(f"publish:{logical_path}")

    def validate_candidate(self, candidate: Path, _rsyslogd: str, _runuser: str, reader: str) -> bool:
        self.operations.append("validate")
        if not self.validator_available or not candidate.is_file():
            return False
        data = candidate.read_bytes()
        selected = f"$FileGroup {reader}\n".encode()
        actions = (
            b"*.*;auth,authpriv.none\t\t-/var/log/syslog\n",
            b"auth,authpriv.*\t\t\t/var/log/auth.log\n",
        )
        if not self.validator_accepts or data.count(selected) != 2:
            return False
        if data.count(b"$FileGroup adm\n") != 3:
            return False
        if data.count(b"$FileCreateMode 0640\n") != 1:
            return False
        return all(
            data.count(action) == 1
            and data.count(selected + action + b"$FileGroup adm\n") == 1
            for action in actions
        )

    def observe_producer(self, _systemctl: str, _rsyslogd: str) -> ProducerObservation:
        self.operations.append("observe")
        if self.observation_sequence:
            return self.observation_sequence.pop(0)
        if self.observation_error or self.observation_transition:
            return ProducerObservation(None, False)
        if self.producer.active is False:
            return ProducerObservation(False, False, self.producer.pid, self.producer.start_identity)
        identity_valid = (
            self.producer.identity_valid
            and self.configured_argv == ["/usr/sbin/rsyslogd", "-n", "-iNONE"]
            and self.running_argv == self.configured_argv
            and self.running_executable == "/usr/sbin/rsyslogd"
            and not self.drop_ins
            and not self.root_directory
            and not self.root_image
            and self.mount_matches
            and self.command_records == 1
            and self.command_record_recognized
        )
        return ProducerObservation(True if identity_valid else None, identity_valid, self.producer.pid, self.producer.start_identity)

    def restart_producer(self, _systemctl: str) -> bool:
        self.operations.append("restart")
        if not self._producer_context_valid():
            return False
        if not self.restart_result:
            self.producer = ProducerObservation(self.restart_observation, self.restart_observation is True)
            return False
        config = (self.root / "etc/rsyslog.conf").read_bytes()
        captures = self._rendered_action_groups(config)
        if captures is None:
            return False
        self.loaded_action_groups = captures
        self.producer = ProducerObservation(True, True, self.producer.pid + 1, f"{self.producer.pid + 1}:9002")
        return True

    def reader_can_read(self, logical_path: str, physical_path: Path, uid: int, gid: int, _runuser: str, _reader: str) -> bool:
        facts = self.files[logical_path]
        return (
            uid != 0 and gid == facts.gid and bool(facts.mode & 0o040)
            and physical_path.is_file()
            and self.physical_inodes.get(logical_path) == physical_path.stat().st_ino
        )

    def _rendered_action_groups(self, data: bytes) -> dict[str, int] | None:
        current = self.groups["adm"].gid
        captures: dict[str, int] = {}
        group_by_name = {name: identity.gid for name, identity in self.groups.items()}
        for line in data.splitlines(keepends=True):
            if line.startswith(b"$FileGroup "):
                name = line[len(b"$FileGroup "):].strip().decode("ascii", "strict")
                if name not in group_by_name:
                    return None
                current = group_by_name[name]
            elif line in (
                b"*.*;auth,authpriv.none\t\t-/var/log/syslog\n",
                b"auth,authpriv.*\t\t\t/var/log/auth.log\n",
            ):
                logical = "/var/log/syslog" if line.startswith(b"*.*") else "/var/log/auth.log"
                if logical in captures:
                    return None
                captures[logical] = current
        return captures if set(captures) == {"/var/log/auth.log", "/var/log/syslog"} else None

    def _producer_context_valid(self) -> bool:
        return (
            self.producer.active is True
            and self.producer.identity_valid
            and self.configured_argv == ["/usr/sbin/rsyslogd", "-n", "-iNONE"]
            and self.running_argv == self.configured_argv
            and self.running_executable == "/usr/sbin/rsyslogd"
            and not self.drop_ins
            and not self.root_directory
            and not self.root_image
            and self.mount_matches
            and self.command_records == 1
            and self.command_record_recognized
            and not self.observation_error
            and not self.observation_transition
        )

    def hup_reopen(self) -> None:
        """Model HUP as reopen-only; it never reloads changed configuration."""
        if not self._producer_context_valid():
            raise InjectedFailure("producer recreation has invalid context")
        self.operations.append("hup")
        for logical in self.loaded_action_groups:
            if logical not in self.files:
                self.recreate(logical)

    def recreate(self, logical_path: str) -> None:
        """Recreate one absent canonical file from the settings loaded by restart."""
        physical = self.root / logical_path.lstrip("/")
        if (
            not self._producer_context_valid()
            or logical_path in self.files
            or logical_path in self.physical_inodes
            or physical.exists()
            or physical.is_symlink()
            or logical_path not in self.loaded_action_groups
        ):
            raise InjectedFailure("producer recreation is not possible")
        try:
            with physical.open("xb"):
                pass
            physical.chmod(0o640)
        except OSError as error:
            raise InjectedFailure(f"producer recreation failed: {error}") from error
        facts = FileFacts(
            uid=0, gid=self.loaded_action_groups[logical_path], mode=0o640,
            ino=1000 + max((facts.ino for facts in self.files.values()), default=0),
        )
        self.files[logical_path] = facts
        self.physical_inodes[logical_path] = physical.stat().st_ino
        self.operations.append(f"recreate:{logical_path}:{facts.gid}")

    def rotate(self, logical_path: str) -> None:
        """Apply the unchanged bare-create profile by inheriting previous attributes."""
        facts = self.files.get(logical_path)
        physical = self.root / logical_path.lstrip("/")
        archive_logical = logical_path + ".1"
        archive = self.root / archive_logical.lstrip("/")
        profile_valid = bool(self.rotation_profile_hashes) and all(
            path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest
            for logical, digest in self.rotation_profile_hashes.items()
            for path in [self.root / logical.lstrip("/")]
        )
        if (
            not self._producer_context_valid()
            or not profile_valid
            or facts is None
            or not physical.is_file()
            or physical.is_symlink()
            or self.physical_inodes.get(logical_path) != physical.stat().st_ino
            or archive_logical in self.files
            or archive.exists()
        ):
            raise InjectedFailure("rotation transition is not possible")
        physical.replace(archive)
        with physical.open("xb"):
            pass
        physical.chmod(facts.mode)
        self.files[logical_path + ".1"] = facts
        self.files[logical_path] = replace(facts, ino=facts.ino + 5000)
        self.physical_inodes[archive_logical] = archive.stat().st_ino
        self.physical_inodes[logical_path] = physical.stat().st_ino
        self.operations.append(f"rotate:{logical_path}")

    def policy_state(self) -> dict[str, object]:
        return {
            "reader": self.reader,
            "users": dict(self.users),
            "groups": dict(self.groups),
            "packages": set(self.packages),
            "configured_argv": list(self.configured_argv),
            "running_argv": list(self.running_argv),
            "running_executable": self.running_executable,
            "drop_ins": list(self.drop_ins),
            "root_directory": self.root_directory,
            "root_image": self.root_image,
            "mount_matches": self.mount_matches,
            "command_records": self.command_records,
            "command_record_recognized": self.command_record_recognized,
            "observation_error": self.observation_error,
            "observation_transition": self.observation_transition,
            "observation_sequence": list(self.observation_sequence),
            "state_uid_overrides": dict(self.state_uid_overrides),
            "group_close_error_for": self.group_close_error_for,
            "primitive_faults": dict(self.primitive_faults),
            "rotation_profile_hashes": dict(self.rotation_profile_hashes),
            "files": dict(self.files),
            "physical_inodes": dict(self.physical_inodes),
            "producer": self.producer,
            "validator_available": self.validator_available,
            "validator_accepts": self.validator_accepts,
            "restart_result": self.restart_result,
            "restart_observation": self.restart_observation,
            "consumer_running": self.consumer_running,
            "failures": dict(self.failures),
            "loaded_action_groups": dict(self.loaded_action_groups),
        }

    def save(self, path: Path) -> None:
        if self.callbacks:
            raise ValueError("callbacks are test-process-only and cannot be persisted")
        if not set(self.primitive_faults).issubset({"candidate_unlink"}):
            raise ValueError("unknown persisted primitive fault")
        payload = {
            "schema": 1,
            "reader": self.reader,
            "users": {name: identity.__dict__ for name, identity in self.users.items()},
            "groups": {name: identity.__dict__ for name, identity in self.groups.items()},
            "packages": sorted(self.packages),
            "files": {name: facts.__dict__ for name, facts in self.files.items()},
            "producer": self.producer.__dict__,
            "consumer_running": self.consumer_running,
            "operations": self.operations,
            "failures": {"|".join(key): value for key, value in self.failures.items()},
            "validator_available": self.validator_available,
            "validator_accepts": self.validator_accepts,
            "restart_result": self.restart_result,
            "restart_observation": self.restart_observation,
            "loaded_action_groups": self.loaded_action_groups,
            "physical_inodes": self.physical_inodes,
            "configured_argv": self.configured_argv,
            "running_argv": self.running_argv,
            "running_executable": self.running_executable,
            "drop_ins": self.drop_ins,
            "root_directory": self.root_directory,
            "root_image": self.root_image,
            "mount_matches": self.mount_matches,
            "command_records": self.command_records,
            "command_record_recognized": self.command_record_recognized,
            "observation_error": self.observation_error,
            "observation_transition": self.observation_transition,
            "observation_sequence": [item.__dict__ for item in self.observation_sequence],
            "state_uid_overrides": self.state_uid_overrides,
            "group_close_error_for": self.group_close_error_for,
            "primitive_faults": self.primitive_faults,
            "rotation_profile_hashes": self.rotation_profile_hashes,
        }
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, root: Path, path: Path) -> "ModelHost":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != 1:
            raise ValueError("unsupported model state schema")
        host = cls(root, payload["reader"])
        host.users = {name: Identity(**identity) for name, identity in payload["users"].items()}
        host.groups = {name: Identity(**identity) for name, identity in payload["groups"].items()}
        host.packages = set(payload["packages"])
        host.files = {name: FileFacts(**facts) for name, facts in payload["files"].items()}
        host.producer = ProducerObservation(**payload["producer"])
        host.consumer_running = payload["consumer_running"]
        host.operations = list(payload["operations"])
        host.failures = {tuple(key.split("|", 1)): value for key, value in payload["failures"].items()}
        host.validator_available = payload["validator_available"]
        host.validator_accepts = payload["validator_accepts"]
        host.restart_result = payload["restart_result"]
        host.restart_observation = payload["restart_observation"]
        host.loaded_action_groups = {name: int(gid) for name, gid in payload["loaded_action_groups"].items()}
        host.physical_inodes = {name: int(ino) for name, ino in payload["physical_inodes"].items()}
        host.configured_argv = list(payload["configured_argv"])
        host.running_argv = list(payload["running_argv"])
        host.running_executable = payload["running_executable"]
        host.drop_ins = list(payload["drop_ins"])
        host.root_directory = payload["root_directory"]
        host.root_image = payload["root_image"]
        host.mount_matches = payload["mount_matches"]
        host.command_records = payload["command_records"]
        host.command_record_recognized = payload["command_record_recognized"]
        host.observation_error = payload["observation_error"]
        host.observation_transition = payload["observation_transition"]
        host.observation_sequence = [ProducerObservation(**item) for item in payload["observation_sequence"]]
        host.state_uid_overrides = {name: int(uid) for name, uid in payload["state_uid_overrides"].items()}
        host.group_close_error_for = payload["group_close_error_for"]
        host.primitive_faults = {name: int(count) for name, count in payload["primitive_faults"].items()}
        if not set(host.primitive_faults).issubset({"candidate_unlink"}):
            raise ValueError("unknown persisted primitive fault")
        host.rotation_profile_hashes = dict(payload["rotation_profile_hashes"])
        return host


def run_staged_entrypoint(argv: list[str], state_path: Path, accepted_helper: Path) -> int:
    """Execute staged production bytes with only the privileged host protocol modeled."""
    if len(argv) < 2 or Path(argv[0]).read_bytes() != accepted_helper.read_bytes():
        raise RuntimeError("staged production helper bytes differ from the accepted source")
    root_index = argv.index("--root") + 1
    root = Path(argv[root_index])
    host = ModelHost.load(root, state_path)
    spec = importlib.util.spec_from_file_location("staged_stock_log_access", argv[0])
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load staged production helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    original_unlink = module.os.unlink
    def faulted_unlink(target, *args, **kwargs):
        if str(target).startswith("candidate-") and host.primitive_faults.get("candidate_unlink", 0):
            host.primitive_faults["candidate_unlink"] -= 1
            raise OSError(5, "injected candidate cleanup unlink failure")
        return original_unlink(target, *args, **kwargs)
    module.os.unlink = faulted_unlink
    try:
        return module.main(argv[1:], host=host)
    finally:
        module.os.unlink = original_unlink
        host.save(state_path)


def snapshot(root: Path, host: ModelHost) -> dict[str, object]:
    """Capture operational state, excluding the helper's private state directory."""
    files: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_file() and "var/lib/detection-engineering" not in str(path):
            files[str(path.relative_to(root))] = path.read_bytes()
    return {
        "bytes": files,
        "facts": dict(host.files),
        "producer": host.producer,
        "consumer": host.consumer_running,
    }
