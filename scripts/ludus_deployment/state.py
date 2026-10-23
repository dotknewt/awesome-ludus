"""Private, durable local state for reusable Ludus deployments.

This module deliberately contains no Ludus client or network operations.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import types
import uuid
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints

from . import models

_SCHEMA = 1
_MAX_DIAGNOSTIC = 64 * 1024
_MAX_JOURNAL = 10 * 1024 * 1024
_SAFE_TEXT = re.compile(r"^[\w .,:;()\[\]{}+/@=-]*$", re.UNICODE)
_RECORD_TYPES = {
    cls.__name__: cls
    for cls in (
        models.ServerKey, models.Capabilities, models.Target, models.Checkout,
        models.Manifest, models.RangeSnapshot, models.HistoryEntry,
        models.UploadEntry, models.RunRecord, models.ObservationRecord,
    )
}


def _default_root() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "awesome-ludus"


def _reject_symlink_ancestors(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"symlink in private state path: {current}")


def _validate_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or "/" in value or "\\" in value or "\0" in value:
        raise ValueError(f"unsafe {label}")
    return value


def _encode(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {"__type__": type(value).__name__, **{field.name: _encode(getattr(value, field.name)) for field in dataclasses.fields(value)}}
    if isinstance(value, Path):
        return {"__path__": str(value)}
    if isinstance(value, tuple):
        return {"__tuple__": [_encode(item) for item in value]}
    if isinstance(value, list):
        return [_encode(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("state mappings require string keys")
        return {key: _encode(item) for key, item in value.items()}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise ValueError(f"unsupported state value: {type(value).__name__}")


def _decode(value: Any, expected: Any = Any) -> Any:
    origin = get_origin(expected)
    args = get_args(expected)
    if isinstance(value, list):
        if expected is not Any and origin is not list:
            raise ValueError("unexpected list in state")
        item_type = args[0] if args else Any
        return [_decode(item, item_type) for item in value]
    if origin is Literal:
        if value not in args or type(value) not in {type(item) for item in args}:
            raise ValueError("invalid literal value in state")
        return value
    if origin in {Union, types.UnionType}:
        if value is None and type(None) in args:
            return None
        for arg in args:
            if arg is type(None):
                continue
            try:
                return _decode(value, arg)
            except (TypeError, ValueError, KeyError):
                pass
        raise ValueError("invalid union value in state")
    if value is None and expected is not Any:
        raise ValueError("unexpected null value in state")
    if isinstance(value, dict):
        if set(value) == {"__path__"} and isinstance(value["__path__"], str):
            result = Path(value["__path__"])
            if expected is not Any and expected is not Path:
                raise ValueError("unexpected path value in state")
            return result
        if set(value) == {"__tuple__"} and isinstance(value["__tuple__"], list):
            if origin is not tuple:
                raise ValueError("unexpected tuple marker in state")
            values = value["__tuple__"]
            if len(args) == 2 and args[1] is Ellipsis:
                return tuple(_decode(item, args[0]) for item in values)
            if len(values) != len(args):
                raise ValueError("tuple arity mismatch in state")
            return tuple(_decode(item, item_type) for item, item_type in zip(values, args))
        if "__type__" in value:
            name = value["__type__"]
            cls = _RECORD_TYPES.get(name)
            if cls is None or (expected is not Any and expected is not cls):
                raise ValueError("unknown or unexpected state record type")
            hints = get_type_hints(cls)
            fields = {field.name for field in dataclasses.fields(cls)}
            if set(value) != fields | {"__type__"}:
                raise ValueError(f"invalid fields for {name}")
            return cls(**{field: _decode(value[field], hints[field]) for field in fields})
        if expected is not Any and origin is not dict:
            raise ValueError("unexpected mapping in state")
        if origin is dict:
            key_type, value_type = args if len(args) == 2 else (Any, Any)
            return {_decode(key, key_type): _decode(item, value_type) for key, item in value.items()}
        return {key: _decode(item) for key, item in value.items()}
    if origin is dict:
        raise ValueError("expected mapping in state")
    if expected is Any:
        return value
    if expected is str and not isinstance(value, str):
        raise ValueError("expected string in state")
    if expected is bool and not isinstance(value, bool):
        raise ValueError("expected boolean in state")
    if expected is int and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError("expected integer in state")
    if expected is float and (not isinstance(value, (int, float)) or isinstance(value, bool)):
        raise ValueError("expected number in state")
    if origin is tuple:
        raise ValueError("expected tagged tuple in state")
    if expected is Path:
        raise ValueError("expected tagged path in state")
    if isinstance(expected, type) and dataclasses.is_dataclass(expected):
        raise ValueError(f"expected {expected.__name__} record in state")
    return value


def _dump_bytes(value: Any) -> bytes:
    return (json.dumps(_encode(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _load_json(path: Path) -> Any:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(f"insecure state record: {path.name}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"state record has unexpected owner: {path.name}")
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"corrupt state record: {path.name}") from exc


def sanitize(text: str, known_secrets: frozenset[str]) -> str:
    """Return bounded safe diagnostics; unsafe/unknown content is suppressed."""
    if not isinstance(text, str):
        return "[diagnostic suppressed]"
    value = text
    for secret in sorted((s for s in known_secrets if s), key=len, reverse=True):
        value = value.replace(secret, "[redacted]")
    # Remove URL credentials/queries entirely rather than trying to redact a
    # potentially incomplete credential grammar.
    value = re.sub(r"\bhttps?://[^\s]+", "[URL suppressed]", value, flags=re.I)
    value = re.sub(r"(?im)\bauthorization\s*[:=]\s*(?:bearer\s+)?[^\r\n,;]+", "[credential suppressed]", value)
    value = re.sub(r"(?i)\bbearer\s+[^\s,;]+", "[credential suppressed]", value)
    value = re.sub(r"(?i)\b(token|password|passwd|secret|credential|api[_-]?key)\s*[:=]\s*[^\s,;]+", "[credential suppressed]", value)
    if not _SAFE_TEXT.fullmatch(value):
        return "[diagnostic suppressed]"
    if len(value.encode("utf-8", errors="replace")) > _MAX_DIAGNOSTIC:
        clipped = value.encode("utf-8", errors="replace")[:_MAX_DIAGNOSTIC - 16].decode("utf-8", errors="ignore")
        value = clipped + " [truncated]"
    return value


class StateStore:
    """Filesystem-backed local state with one process-shared mutation lock."""

    def __init__(self, root: Path | None = None):
        self.root = Path(root).expanduser() if root is not None else _default_root()
        self.root = self.root.absolute()
        _reject_symlink_ancestors(self.root)
        self._local = threading.local()
        self._ensure_root()

    def _ensure_root(self) -> None:
        _reject_symlink_ancestors(self.root)
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise
        info = self.root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("private state root must be a real directory")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError("private state root has unexpected owner")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("private state root must have mode 0700")

    def _path(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts)
        _reject_symlink_ancestors(path)
        self._verify_private_ancestors(path)
        return path

    def _verify_private_ancestors(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("state path escaped its root") from exc
        current = self.root
        for component in (None, *relative.parts):
            if component is not None:
                current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError(f"insecure private directory: {current.name}")
            elif stat.S_ISLNK(info.st_mode):
                raise ValueError(f"symlink in private state path: {current}")

    def _ensure_dir(self, path: Path) -> None:
        _reject_symlink_ancestors(path)
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("private directory escaped state root") from exc
        current = self.root
        for component in relative.parts:
            current = current / component
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError(f"insecure private directory: {current.name}")

    @contextlib.contextmanager
    def _lock(self, name: str):
        self._ensure_root()
        lock_path = self._path(name)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("insecure state lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("state lock is contended") from exc
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def mutation_lock(self):
        @contextlib.contextmanager
        def held():
            with self._lock("mutation.lock"):
                depth = getattr(self._local, "mutation_depth", 0)
                self._local.mutation_depth = depth + 1
                try:
                    yield
                finally:
                    self._local.mutation_depth -= 1
        return held()

    def _require_mutation_lock(self) -> None:
        if not getattr(self._local, "mutation_depth", 0):
            raise RuntimeError("mutation_lock() is required for state mutation")

    def run_lock(self, run_id: str):
        return self._evidence_lock(run_id, "run")

    def observation_lock(self, observation_id: str):
        return self._evidence_lock(observation_id, "observation")

    def _evidence_lock(self, record_id: str, kind: str):
        @contextlib.contextmanager
        def held():
            lock_record_id = _validate_component(record_id, f"{kind} id")
            key = (kind, lock_record_id)
            held_ids = getattr(self._local, "evidence_locks", set())
            if key in held_ids:
                raise RuntimeError(f"nested {kind} lock is not supported")
            with self._lock(f"{kind}-{lock_record_id}.lock"):
                self._local.evidence_locks = held_ids | {key}
                try:
                    yield
                finally:
                    remaining = set(self._local.evidence_locks)
                    remaining.discard(key)
                    self._local.evidence_locks = remaining
        return held()

    def _atomic_write(self, path: Path, data: bytes) -> None:
        _reject_symlink_ancestors(path)
        self._ensure_dir(path.parent)
        fd, temporary = tempfile.mkstemp(prefix=".write-", suffix=".tmp", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
            raise

    def _read_envelope(self, path: Path, kind: str) -> dict[str, Any]:
        raw = _load_json(path)
        if not isinstance(raw, dict) or set(raw) - {"schema", "kind", "payload", "key", "identity", "scope_digest"} or raw.get("schema") != _SCHEMA or raw.get("kind") != kind or not isinstance(raw.get("payload"), dict):
            raise ValueError(f"invalid {kind} state record")
        if kind == "upload" and (
            set(raw) != {"schema", "kind", "payload", "key", "identity", "scope_digest"}
            or not isinstance(raw.get("key"), str)
            or not isinstance(raw.get("identity"), str)
            or not isinstance(raw.get("scope_digest"), str)
        ):
            raise ValueError("invalid upload key record")
        if kind != "upload" and set(raw) != {"schema", "kind", "payload"}:
            raise ValueError(f"invalid {kind} envelope")
        return raw

    @staticmethod
    def _scope_digest(server: models.ServerKey) -> str:
        return hashlib.sha256(server.access_scope.encode("utf-8")).hexdigest()

    @classmethod
    def _key_digest(cls, server: models.ServerKey, role: str) -> str:
        blob = json.dumps([server.identity, cls._scope_digest(server), role], ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def _upload_dir(self) -> Path:
        return self._path("uploads")

    def _entry_path(self, entry: models.UploadEntry) -> Path:
        key = self._key_digest(entry.server, entry.role)
        return self._path("uploads", f"{key}.json")

    def load_entry(self, server: models.ServerKey, role: str) -> models.UploadEntry | None:
        _validate_component(role, "role")
        path = self._path("uploads", f"{self._key_digest(server, role)}.json")
        if not path.exists():
            return None
        entry = self._decode_upload(path, server)
        if entry.role != role:
            raise ValueError("upload cache key mismatch")
        if entry.status == "in-flight":
            return dataclasses.replace(entry, status="unknown")
        return entry

    def _decode_upload(self, path: Path, server: models.ServerKey | None = None) -> models.UploadEntry:
        raw = self._read_envelope(path, "upload")
        key = raw["key"]
        if not re.fullmatch(r"[0-9a-f]{64}", key) or path.stem != key:
            raise ValueError("upload filename/key mismatch")
        payload = dict(raw["payload"])
        if payload.get("__type__") != "UploadEntry":
            raise ValueError("invalid upload payload type")
        role = payload.get("role")
        _validate_component(role, "stored role")
        expected_key = hashlib.sha256(
            json.dumps([raw["identity"], raw["scope_digest"], role], ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        if raw["scope_digest"] != raw["scope_digest"].lower() or not re.fullmatch(r"[0-9a-f]{64}", raw["scope_digest"]) or expected_key != key:
            raise ValueError("upload descriptor/key mismatch")
        embedded_server = server or models.ServerKey("[redacted]", "[redacted]")
        if server is not None and (raw["identity"] != server.identity or raw["scope_digest"] != self._scope_digest(server)):
            raise ValueError("upload server key mismatch")
        payload["server"] = _encode(embedded_server)
        entry = _decode(payload, models.UploadEntry)
        if server is not None and self._key_digest(server, entry.role) != key:
            raise ValueError("upload cache key mismatch")
        return entry

    def save_entry(self, entry: models.UploadEntry) -> None:
        self._require_mutation_lock()
        _validate_component(entry.role, "role")
        if entry.status not in {"success", "unknown", "in-flight"}:
            raise ValueError("invalid upload status")
        payload = _encode(entry)
        payload.pop("server")
        # Persist server key in the payload solely as its stable key digest;
        # credentials never belong in cache metadata.
        key = self._key_digest(entry.server, entry.role)
        envelope = {
            "schema": _SCHEMA,
            "kind": "upload",
            "key": key,
            "identity": entry.server.identity,
            "scope_digest": self._scope_digest(entry.server),
            "payload": payload,
        }
        self._atomic_write(self._entry_path(entry), _dump_bytes(envelope))

    def begin_upload(self, entry: models.UploadEntry) -> None:
        self._require_mutation_lock()
        if entry.status != "in-flight":
            raise ValueError("begin_upload requires in-flight status")
        _validate_component(entry.role, "role")
        directory = self._upload_dir()
        records = []
        if directory.exists():
            for path in directory.iterdir():
                if path.suffix != ".json":
                    raise ValueError("unexpected upload-state file")
                decoded = self._decode_upload(path)
                raw = self._read_envelope(path, "upload")
                records.append((path, raw, decoded))
        for path, raw, decoded in records:
            if decoded.role == entry.role:
                # Preserve each old entry as unknown before reserving the target.
                payload = dict(raw["payload"])
                payload["status"] = "unknown"
                self._atomic_write(path, _dump_bytes({**raw, "payload": payload}))
        self.save_entry(entry)

    def reset_upload_history(self) -> int:
        self._require_mutation_lock()
        directory = self._upload_dir()
        if not directory.exists():
            return 0
        paths = list(directory.iterdir())
        for path in paths:
            if path.suffix != ".json":
                raise ValueError("unexpected upload-state file")
            self._decode_upload(path)
        count = 0
        for path in paths:
            path.unlink()
            count += 1
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return count

    def new_run(self, target: models.Target, scope: models.Scope, checkout: models.Checkout, config_digest: str) -> models.RunRecord:
        run_id = str(uuid.uuid4())
        self._ensure_dir(self._path("runs"))
        self._ensure_dir(self.stage_root(run_id))
        self._ensure_dir(self.evidence_dir(run_id))
        return models.RunRecord(run_id, target, scope, checkout, config_digest, "created", 0, 0, None, (), None, None, None, "unknown")

    def _record_path(self, category: str, record_id: str) -> Path:
        return self._path(category, f"{_validate_component(record_id, 'record id')}.json")

    def save_run(self, run: models.RunRecord) -> None:
        self._require_mutation_lock()
        self._atomic_write(self._record_path("runs", run.run_id), _dump_bytes({"schema": _SCHEMA, "kind": "run", "payload": _encode(run)}))

    def load_run(self, run_id: str) -> models.RunRecord:
        raw = self._read_envelope(self._record_path("runs", run_id), "run")
        record = _decode(raw["payload"], models.RunRecord)
        if record.run_id != run_id:
            raise ValueError("run record id mismatch")
        return record

    def new_observation(self, target: models.Target, source_run_id: str | None, history_id: str | None) -> models.ObservationRecord:
        record = models.ObservationRecord(str(uuid.uuid4()), target, source_run_id, history_id, "unknown", "unknown")
        self._ensure_dir(self._path("observations"))
        self._ensure_dir(self.evidence_dir(record.observation_id))
        return record

    def save_observation(self, record: models.ObservationRecord) -> None:
        if ("observation", record.observation_id) not in getattr(self._local, "evidence_locks", set()):
            raise RuntimeError("observation_lock() is required to save observation state")
        self._atomic_write(self._record_path("observations", record.observation_id), _dump_bytes({"schema": _SCHEMA, "kind": "observation", "payload": _encode(record)}))

    def stage_root(self, run_id: str) -> Path:
        return self._path("stages", _validate_component(run_id, "run id"))

    def evidence_dir(self, record_id: str) -> Path:
        return self._path("evidence", _validate_component(record_id, "record id"))

    def write_event(self, record_id: str, event: dict[str, object]) -> None:
        _validate_component(record_id, "record id")
        held_locks = getattr(self._local, "evidence_locks", set())
        if not any(held_id == record_id for _, held_id in held_locks):
            raise RuntimeError("run_lock() or observation_lock() is required to write evidence")
        if not isinstance(event, dict):
            raise ValueError("event must be a mapping")
        directory = self.evidence_dir(record_id)
        self._ensure_dir(directory)
        # Strict allowlist: arbitrary messages, output, URLs, nested payloads,
        # and secret-like fields are never persisted or displayed.
        event_type = event.get("type")
        allowed_types = {"upload", "phase", "launch", "outcome"}
        safe_type = event_type if isinstance(event_type, str) and event_type in allowed_types else "unknown"
        safe_event: dict[str, str] = {"type": safe_type}
        role = event.get("role")
        if isinstance(role, str) and self._is_run_role(record_id, role):
            safe_event["role"] = role
        disposition = event.get("disposition")
        if isinstance(disposition, str) and disposition in {"accepted", "confirmed", "success", "failure", "unknown", "blocked"}:
            safe_event["disposition"] = disposition
        phase = event.get("phase")
        if isinstance(phase, str) and phase in {
            "created", "preflight", "staged", "uploading", "upload", "verified",
            "launch-reserved", "launch-unknown", "launch", "monitor", "complete",
        }:
            safe_event["phase"] = phase
        path = directory / "events.jsonl"
        _reject_symlink_ancestors(path)
        existing_size = self._validated_journal_size(path) if path.exists() else 0
        line = _dump_bytes(safe_event)
        marker = _dump_bytes({"type": "truncated", "disposition": "unknown"})
        if self._journal_ends_with_marker(path):
            return
        reserved_limit = _MAX_JOURNAL - len(marker)
        if existing_size + len(line) > reserved_limit:
            if existing_size + len(marker) > _MAX_JOURNAL:
                raise ValueError("journal is full without room for a complete truncation marker")
            self._append_durable(path, marker)
            return
        self._append_durable(path, line)

    def _is_run_role(self, run_id: str, role: str) -> bool:
        try:
            run = self.load_run(run_id)
        except (OSError, ValueError):
            return False
        expected_identity = run.target.server.identity
        expected_scope = self._scope_digest(run.target.server)
        directory = self._upload_dir()
        if not directory.exists():
            return False
        for path in directory.iterdir():
            if path.suffix != ".json":
                continue
            entry = self._decode_upload(path)
            raw = self._read_envelope(path, "upload")
            if (
                entry.role == role
                and entry.run_id == run_id
                and entry.status in {"success", "unknown", "in-flight"}
                and raw["identity"] == expected_identity
                and raw["scope_digest"] == expected_scope
            ):
                return True
        return False

    def _validated_journal_size(self, path: Path) -> int:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("insecure evidence journal")
        size = info.st_size
        if size > _MAX_JOURNAL:
            raise ValueError("evidence journal exceeds configured limit")
        with path.open("rb") as stream:
            for line in stream:
                if not line.endswith(b"\n"):
                    raise ValueError("incomplete JSONL journal record")
                try:
                    record = json.loads(line)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise ValueError("corrupt JSONL journal record") from exc
                if not isinstance(record, dict) or not isinstance(record.get("type"), str):
                    raise ValueError("invalid JSONL journal record")
        return size

    @staticmethod
    def _journal_ends_with_marker(path: Path) -> bool:
        if not path.exists() or path.stat().st_size == 0:
            return False
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 256))
            tail = stream.read()
        final = tail.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            record = json.loads(final)
        except (UnicodeError, json.JSONDecodeError):
            return False
        return isinstance(record, dict) and record.get("type") == "truncated"

    def _append_durable(self, path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("insecure evidence journal")
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def cleanup_stage(self, run_id: str) -> None:
        if ("run", run_id) not in getattr(self._local, "evidence_locks", set()):
            raise RuntimeError("run_lock() is required to clean staged data")
        stage = self.stage_root(run_id)
        if not stage.exists():
            return
        _reject_symlink_ancestors(stage)
        info = stage.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("unsafe stage directory")
        shutil.rmtree(stage)
