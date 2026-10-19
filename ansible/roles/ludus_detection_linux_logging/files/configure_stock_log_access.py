#!/usr/bin/env python3
"""Apply the fixed Debian Bookworm policy for two canonical stock logs.

This is a private role helper, not a generic permission or configuration API.
The injectable ``host`` argument exists solely to model privileged host facts in
offline role tests; all policy, profile parsing and file content I/O stays here.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any


READERS = ("splunkfwd", "splunk")
EXPECTED_ARGV = ["/usr/sbin/rsyslogd", "-n", "-iNONE"]
CANONICAL = ("/var/log/auth.log", "/var/log/syslog")
STATE_DIRECTORY = "/var/lib/detection-engineering/stock-log-access"
APPLIED_PATH = STATE_DIRECTORY + "/applied.json"
LOCK_PATH = STATE_DIRECTORY + "/lock"
RSYSLOG_PATH = "/etc/rsyslog.conf"
ACTION_LINES = (
    b"*.*;auth,authpriv.none\t\t-/var/log/syslog\n",
    b"auth,authpriv.*\t\t\t/var/log/auth.log\n",
)
PROFILE_MANIFEST_SHA256 = "40d5f3b649ac755f6c97a0e353939c6a8f2bcec9d472aa183f45ec902c8010ac"


class PolicyError(RuntimeError):
    """A safe refusal of an unsupported or changed host state."""


class _OwnedOperationError(PolicyError):
    """Expected operation failure plus ordered owned-resource diagnostics."""

    def __init__(self, primary: Exception, cleanup_errors: list[dict[str, Any]], changed_paths: list[str] | None = None) -> None:
        super().__init__(str(primary))
        self.primary = primary
        self.cleanup_errors = cleanup_errors
        self.changed_paths = [] if changed_paths is None else changed_paths


def _cleanup_record(operation: str, resource: str, error: OSError, *, unconfirmed: bool = False) -> dict[str, Any]:
    message = str(error)
    if unconfirmed:
        message += "; removal unconfirmed"
    return {
        "operation": operation,
        "resource": resource,
        "errno": error.errno,
        "message": message,
    }


def _close_once(fd: int, resource: str) -> dict[str, Any] | None:
    try:
        os.close(fd)
    except OSError as error:
        return _cleanup_record("close", resource, error)
    return None


def _raise_with_cleanup(primary: Exception, cleanup_errors: list[dict[str, Any]], changed_paths: list[str] | None = None) -> None:
    if isinstance(primary, _OwnedOperationError):
        raise _OwnedOperationError(
            primary.primary,
            [*primary.cleanup_errors, *cleanup_errors],
            [*primary.changed_paths, *(changed_paths or [])],
        ) from primary
    if cleanup_errors or changed_paths:
        raise _OwnedOperationError(primary, cleanup_errors, changed_paths) from primary
    raise primary


def _has_extended_acl(target: Any, *, follow_symlinks: bool = False) -> bool:
    try:
        if isinstance(target, int):
            return bool(os.getxattr(target, "system.posix_acl_access"))
        return bool(os.getxattr(target, "system.posix_acl_access", follow_symlinks=follow_symlinks))
    except AttributeError as exc:
        raise PolicyError("ACL observation is unavailable") from exc
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return False
        raise PolicyError(f"ACL observation failed: {exc}") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _physical(root: Path, logical: str) -> Path:
    return root / logical.lstrip("/")


def _exact_original(profile_dir: Path) -> bytes:
    return (profile_dir / "rsyslog.conf").read_bytes()


def render_candidate(source: bytes, reader: str) -> bytes:
    """Return the deterministic legacy-directive candidate or refuse adoption."""
    if reader not in READERS:
        raise PolicyError("reader is not one of the two approved package readers")
    # Generated configurations are accepted only for their own reader.
    for known_reader in READERS:
        marker = f"$FileGroup {known_reader}\n".encode()
        if marker in source:
            if known_reader != reader:
                raise PolicyError("configuration was generated for a different reader")
            if source.count(marker) != 2:
                raise PolicyError("generated configuration has an unexpected grant count")
            for action in ACTION_LINES:
                bracket = marker + action + b"$FileGroup adm\n"
                if source.count(bracket) != 1:
                    raise PolicyError("generated canonical action is not exactly bracketed")
            return source
    candidate = source
    for action in ACTION_LINES:
        if candidate.count(action) != 1:
            raise PolicyError("canonical selector is missing or ambiguous")
        candidate = candidate.replace(
            action,
            f"$FileGroup {reader}\n".encode() + action + b"$FileGroup adm\n",
            1,
        )
    return candidate


def _load_manifest(profile_dir: Path) -> dict[str, Any]:
    try:
        manifest_bytes = (profile_dir / "manifest.json").read_bytes()
        if _sha256(manifest_bytes) != PROFILE_MANIFEST_SHA256:
            raise PolicyError("profile manifest bytes are not the pinned reviewed manifest")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"invalid profile manifest: {exc}") from exc
    if manifest.get("schema") != 1:
        raise PolicyError("unsupported profile manifest schema")
    expected_keys = {"schema", "profile", "required", "optional_rotation", "provenance_only"}
    if set(manifest) != expected_keys:
        raise PolicyError("profile manifest fields are not fixed")
    for section in ("required", "optional_rotation", "provenance_only"):
        for entry in manifest[section]:
            bundle = profile_dir / entry["bundle"]
            try:
                data = bundle.read_bytes()
            except OSError as exc:
                raise PolicyError(f"missing profile bundle {entry['bundle']}") from exc
            if _sha256(data) != entry["sha256"]:
                raise PolicyError(f"profile bundle hash changed: {entry['bundle']}")
            if not entry.get("url") or not entry.get("version"):
                raise PolicyError("profile provenance is incomplete")
    return manifest


def _inventory_files(directory: Path) -> set[str]:
    if not directory.is_dir() or directory.is_symlink():
        raise PolicyError(f"required include directory is unavailable: {directory}")
    names: set[str] = set()
    for item in directory.iterdir():
        if item.is_symlink() or not item.is_file():
            raise PolicyError(f"nested, linked or non-file include is unsupported: {item}")
        names.add(item.name)
    return names


def validate_profile(root: Path | str, profile_dir: Path | str) -> SimpleNamespace:
    """Validate all effective supported bytes and return their immutable snapshot."""
    root, profile_dir = Path(root), Path(profile_dir)
    manifest = _load_manifest(profile_dir)
    snapshot: dict[str, str] = {}
    original = _exact_original(profile_dir)
    generated_reader: str | None = None
    for entry in manifest["required"]:
        target = _physical(root, entry["target"])
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise PolicyError(f"required target unavailable: {entry['target']}") from exc
        if entry["target"] == RSYSLOG_PATH:
            if data == original:
                source_kind = "original"
            else:
                matches = []
                for reader in READERS:
                    try:
                        if render_candidate(original, reader) == data:
                            matches.append(reader)
                    except PolicyError:
                        pass
                if len(matches) != 1:
                    raise PolicyError("rsyslog configuration is not an admitted form")
                source_kind, generated_reader = "generated", matches[0]
        elif _sha256(data) != entry["sha256"]:
            raise PolicyError(f"required target bytes changed: {entry['target']}")
        snapshot[entry["target"]] = _sha256(data)

    if _inventory_files(_physical(root, "/etc/rsyslog.d")):
        raise PolicyError("stock rsyslog include glob must have no matches")
    allowed_rotation = {Path(e["target"]).name: e for e in manifest["optional_rotation"]}
    rotation_names = _inventory_files(_physical(root, "/etc/logrotate.d"))
    if not rotation_names.issubset({"rsyslog", *allowed_rotation}):
        raise PolicyError("unknown logrotate fragment")
    for name in rotation_names - {"rsyslog"}:
        entry = allowed_rotation[name]
        data = _physical(root, entry["target"]).read_bytes()
        if _sha256(data) != entry["sha256"]:
            raise PolicyError(f"optional rotation fragment changed: {name}")
        snapshot[entry["target"]] = _sha256(data)
    normalized = dict(snapshot)
    normalized[RSYSLOG_PATH] = _sha256(original)
    return SimpleNamespace(
        source_kind=source_kind,
        generated_reader=generated_reader,
        snapshot=snapshot,
        manifest=manifest,
        fingerprint=_sha256(json.dumps(normalized, sort_keys=True).encode()),
    )


class NativeHost:
    """Native privileged adapter. It deliberately has no alternate-root mode."""

    def checkpoint(self, _operation: str, _when: str) -> None:
        return None

    def state_uid(self, _logical_path: str, actual_uid: int) -> int:
        return actual_uid

    @staticmethod
    def _decimal_identity(value: str) -> int | None:
        if not value or not value.isascii() or not value.isdecimal():
            return None
        return int(value)

    def package_installed(self, package: str, command: str) -> bool:
        result = subprocess.run(
            [command, "-W", "-f=${db:Status-Status}", package],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "installed"

    def lookup_user(self, name: str, command: str):
        result = subprocess.run([command, "passwd", name], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return None
        fields = result.stdout.rstrip("\n").split(":")
        if len(fields) != 7 or fields[0] != name:
            return None
        uid = self._decimal_identity(fields[2])
        gid = self._decimal_identity(fields[3])
        if uid is None or gid is None:
            return None
        return SimpleNamespace(name=name, uid=uid, gid=gid)

    def lookup_group(self, name: str, command: str):
        result = subprocess.run([command, "group", name], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return None
        fields = result.stdout.rstrip("\n").split(":")
        if len(fields) != 4 or fields[0] != name:
            return None
        gid = self._decimal_identity(fields[2])
        if gid is None:
            return None
        return SimpleNamespace(name=name, uid=gid, gid=gid)

    def file_facts(self, _logical_path: str, physical_path: Path):
        try:
            info = physical_path.lstat()
        except OSError:
            return None
        symlink = stat.S_ISLNK(info.st_mode)
        acl = _has_extended_acl(physical_path, follow_symlinks=False)
        trusted = True
        parent = physical_path.parent
        while True:
            try:
                parent_info = parent.lstat()
            except OSError:
                trusted = False
                break
            if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode) or
                    parent_info.st_uid != 0 or parent_info.st_mode & 0o022):
                trusted = False
            if parent == parent.parent:
                break
            parent = parent.parent
        return SimpleNamespace(
            uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
            nlink=info.st_nlink, dev=info.st_dev, ino=info.st_ino,
            regular=stat.S_ISREG(info.st_mode), symlink=symlink,
            extended_acl=acl, trusted_parents=trusted,
        )

    def set_group(self, logical_path: str, physical_path: Path, gid: int, expected: Any) -> None:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        parts = physical_path.parts
        if not physical_path.is_absolute() or not parts:
            raise PolicyError("canonical source path is not absolute")
        parent_fd: int | None = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        file_fd: int | None = None
        try:
            for part in parts[1:-1]:
                assert parent_fd is not None
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                old_fd, parent_fd = parent_fd, None
                close_error = _close_once(old_fd, str(physical_path.parent))
                if close_error is not None:
                    next_error = _close_once(next_fd, str(physical_path.parent))
                    _raise_with_cleanup(
                        OSError(close_error["errno"], close_error["message"]),
                        [] if next_error is None else [next_error],
                    )
                parent_fd = next_fd
            assert parent_fd is not None
            file_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
        except (PolicyError, OSError) as exc:
            cleanup_errors: list[dict[str, Any]] = []
            if file_fd is not None:
                fd, file_fd = file_fd, None
                error = _close_once(fd, logical_path)
                if error is not None:
                    cleanup_errors.append(error)
            if parent_fd is not None:
                fd, parent_fd = parent_fd, None
                error = _close_once(fd, str(physical_path.parent))
                if error is not None:
                    cleanup_errors.append(error)
            primary = exc if isinstance(exc, PolicyError) else PolicyError(f"source path changed before group update: {exc}")
            _raise_with_cleanup(primary, cleanup_errors)
        parent_to_close, parent_fd = parent_fd, -1
        parent_close_error = _close_once(parent_to_close, str(physical_path.parent))
        if parent_close_error is not None:
            cleanup_errors: list[dict[str, Any]] = []
            if file_fd is not None:
                file_to_close, file_fd = file_fd, None
                error = _close_once(file_to_close, logical_path)
                if error is not None:
                    cleanup_errors.append(error)
            _raise_with_cleanup(OSError(parent_close_error["errno"], parent_close_error["message"]), cleanup_errors)
        assert file_fd is not None
        primary_error: Exception | None = None
        group_changed = False
        try:
            before = os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    (before.st_dev, before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) !=
                    (expected.dev, expected.ino, expected.uid, expected.gid, expected.mode)):
                raise PolicyError("source changed before group update")
            if _has_extended_acl(file_fd):
                raise PolicyError("source gained an extended ACL before group update")
            os.fchown(file_fd, -1, gid)
            group_changed = True
        except (PolicyError, OSError) as error:
            primary_error = error
        finally:
            file_to_close, file_fd = file_fd, None
            close_error = _close_once(file_to_close, logical_path)
        if primary_error is not None:
            _raise_with_cleanup(primary_error, [] if close_error is None else [close_error], [logical_path] if group_changed else [])
        if close_error is not None:
            _raise_with_cleanup(OSError(close_error["errno"], close_error["message"]), [], [logical_path] if group_changed else [])

    def after_publish(self, _logical_path: str, _physical_path: Path) -> None:
        return None

    def validate_candidate(self, candidate: Path, rsyslogd: str, runuser: str, reader: str) -> bool:
        if not (Path(rsyslogd).is_file() and os.access(rsyslogd, os.X_OK)):
            return False
        result = subprocess.run(
            [rsyslogd, "-N1", "-f", str(candidate)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        return result.returncode == 0

    @staticmethod
    def _decode_exec_start(value: str) -> list[str] | None:
        records = re.findall(r"\{([^{}]*)\}", value)
        if len(records) != 1 or value.strip() != "{" + records[0] + "}":
            return None
        fields: dict[str, str] = {}
        for raw in records[0].split(";"):
            raw = raw.strip()
            if not raw:
                continue
            if "=" not in raw:
                return None
            key, item = raw.split("=", 1)
            if key.strip() in fields:
                return None
            fields[key.strip()] = item.strip()
        if fields.get("path") != EXPECTED_ARGV[0] or fields.get("argv[]") != " ".join(EXPECTED_ARGV):
            return None
        if fields.get("ignore_errors") not in (None, "no"):
            return None
        if not set(fields).issubset({"path", "argv[]", "ignore_errors", "start_time", "stop_time", "pid", "code", "status"}):
            return None
        return list(EXPECTED_ARGV)

    def observe_producer(self, systemctl: str, rsyslogd: str):
        properties = ["LoadState", "ActiveState", "SubState", "MainPID", "ExecStart", "DropInPaths", "RootDirectory", "RootImage"]
        result = subprocess.run(
            [systemctl, "show", "rsyslog.service", "--no-pager", *[f"--property={p}" for p in properties]],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            return SimpleNamespace(active=None, identity_valid=False)
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" not in line:
                return SimpleNamespace(active=None, identity_valid=False)
            key, value = line.split("=", 1)
            if key in values or key not in properties:
                return SimpleNamespace(active=None, identity_valid=False)
            values[key] = value
        if set(values) != set(properties):
            return SimpleNamespace(active=None, identity_valid=False)
        if values["LoadState"] != "loaded":
            if values["LoadState"] in {"not-found", "masked", "error"}:
                return SimpleNamespace(active=False, identity_valid=False)
            return SimpleNamespace(active=None, identity_valid=False)
        if values["ActiveState"] in {"inactive", "failed"}:
            return SimpleNamespace(active=False, identity_valid=False)
        if values["ActiveState"] != "active" or values["SubState"] != "running":
            return SimpleNamespace(active=None, identity_valid=False)
        if values["DropInPaths"] or values["RootDirectory"] or values["RootImage"]:
            return SimpleNamespace(active=None, identity_valid=False)
        if self._decode_exec_start(values["ExecStart"]) != EXPECTED_ARGV:
            return SimpleNamespace(active=None, identity_valid=False)
        try:
            pid = int(values["MainPID"])
            if pid <= 0:
                raise ValueError
            proc = Path("/proc") / str(pid)
            stat_before = (proc / "stat").read_text().split()[21]
            executable = os.readlink(proc / "exe")
            argv = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
            process_root = os.path.realpath(proc / "root")
            process_mount = os.readlink(proc / "ns/mnt")
            self_mount = os.readlink("/proc/self/ns/mnt")
            stat_after = (proc / "stat").read_text().split()[21]
        except (OSError, ValueError, IndexError):
            return SimpleNamespace(active=None, identity_valid=False)
        pid_recheck = subprocess.run(
            [systemctl, "show", "rsyslog.service", "--no-pager", "--property=MainPID"],
            capture_output=True, text=True, check=False,
        )
        if pid_recheck.returncode != 0 or pid_recheck.stdout != f"MainPID={pid}\n":
            return SimpleNamespace(active=None, identity_valid=False)
        valid = (
            executable == os.path.realpath(rsyslogd) == EXPECTED_ARGV[0]
            and argv == [part.encode() for part in EXPECTED_ARGV]
            and process_root == "/" and process_mount == self_mount
            and stat_before == stat_after
        )
        return SimpleNamespace(active=True if valid else None, identity_valid=valid, pid=pid, start_identity=f"{pid}:{stat_after}")

    def restart_producer(self, systemctl: str) -> bool:
        return subprocess.run([systemctl, "restart", "rsyslog.service"], check=False).returncode == 0

    def reader_can_read(self, _logical_path: str, physical_path: Path, uid: int, gid: int, runuser: str, reader: str) -> bool:
        if uid == 0 or gid == 0:
            return False
        return subprocess.run(
            [runuser, "-u", reader, "--", "/usr/bin/test", "-r", str(physical_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        ).returncode == 0


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/")
    parser.add_argument("--reader", required=True, choices=READERS)
    parser.add_argument("--profile-dir", required=True)
    parser.add_argument("--dpkg-query", default="/usr/bin/dpkg-query")
    parser.add_argument("--getent", default="/usr/bin/getent")
    parser.add_argument("--systemctl", default="/usr/bin/systemctl")
    parser.add_argument("--rsyslogd", default="/usr/sbin/rsyslogd")
    parser.add_argument("--runuser", default="/usr/sbin/runuser")
    return parser.parse_args(argv)


def _safe_source(host: Any, logical: str, path: Path, allowed_groups: set[int]):
    facts = host.file_facts(logical, path)
    if facts is None:
        raise PolicyError(f"required source is missing: {logical}")
    if (facts.symlink or not facts.regular or facts.nlink != 1 or facts.uid != 0 or
            facts.mode != 0o640 or facts.gid not in allowed_groups or
            facts.extended_acl or not facts.trusted_parents):
        raise PolicyError(f"unsafe canonical source: {logical}")
    return facts


def _same_file_facts(left: Any, right: Any) -> bool:
    fields = (
        "uid", "gid", "mode", "nlink", "dev", "ino", "regular", "symlink",
        "extended_acl", "trusted_parents",
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def _safe_config(host: Any, logical: str, path: Path):
    facts = host.file_facts(logical, path)
    if facts is None:
        raise PolicyError(f"required configuration is missing: {logical}")
    if (facts.symlink or not facts.regular or facts.nlink != 1 or facts.uid != 0 or
            facts.mode & 0o022 or facts.extended_acl or not facts.trusted_parents):
        raise PolicyError(f"unsafe required configuration: {logical}")
    return facts


def _open_parent_nofollow(path: Path, resource: str | None = None) -> tuple[int, str]:
    if not path.is_absolute() or len(path.parts) < 2:
        raise PolicyError("publication target is not an absolute file path")
    current: int | None = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    close_resource = str(Path(resource).parent) if resource is not None else str(path.parent)
    try:
        for part in path.parts[1:-1]:
            assert current is not None
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            old_fd, current = current, None
            close_error = _close_once(old_fd, close_resource)
            if close_error is not None:
                next_error = _close_once(next_fd, close_resource)
                _raise_with_cleanup(
                    OSError(close_error["errno"], close_error["message"]),
                    [] if next_error is None else [next_error],
                )
            current = next_fd
        assert current is not None
        return current, path.name
    except (PolicyError, OSError) as primary:
        cleanup_errors: list[dict[str, Any]] = []
        if current is not None:
            fd, current = current, None
            error = _close_once(fd, close_resource)
            if error is not None:
                cleanup_errors.append(error)
        _raise_with_cleanup(primary, cleanup_errors)
        raise AssertionError("unreachable")


def _atomic_write_at(
    directory_fd: int,
    target_name: str,
    data: bytes,
    mode: int,
    *,
    owner: tuple[int, int] | None = None,
    checkpoint: Any = None,
    replace_operation: str,
    directory_operation: str,
    on_replaced: Any = None,
    on_leftover: Any = None,
    temp_resource: Any = None,
) -> None:
    temporary_name = ".stock-access-" + secrets.token_hex(12)
    fd = os.open(
        temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode, dir_fd=directory_fd,
    )
    early_error: OSError | None = None
    close_error: dict[str, Any] | None = None
    try:
        try:
            os.fchmod(fd, mode)
            if owner is not None:
                os.fchown(fd, *owner)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            early_error = exc
    finally:
        fd_to_close, fd = fd, -1
        close_resource = temp_resource(temporary_name) if temp_resource is not None else temporary_name
        close_error = _close_once(fd_to_close, close_resource)
    if early_error is not None:
        cleanup_errors = [] if close_error is None else [close_error]
        changed_paths: list[str] = []
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            leftover = on_leftover(temporary_name) if on_leftover is not None else temporary_name
            cleanup_errors.append(_cleanup_record("unlink", leftover, cleanup_error, unconfirmed=True))
            changed_paths.append(leftover)
        _raise_with_cleanup(early_error, cleanup_errors, changed_paths)
    if close_error is not None:
        primary = OSError(close_error["errno"], close_error["message"])
        cleanup_errors = []
        changed_paths = []
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            leftover = on_leftover(temporary_name) if on_leftover is not None else temporary_name
            cleanup_errors.append(_cleanup_record("unlink", leftover, cleanup_error, unconfirmed=True))
            changed_paths.append(leftover)
        _raise_with_cleanup(primary, cleanup_errors, changed_paths)
    temporary_exists = True
    try:
        if checkpoint is not None:
            checkpoint(replace_operation, "before")
        os.replace(
            temporary_name, target_name,
            src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
        )
        temporary_exists = False
        if on_replaced is not None:
            on_replaced()
        if checkpoint is not None:
            checkpoint(replace_operation, "after")
            checkpoint(directory_operation, "before")
        os.fsync(directory_fd)
        if checkpoint is not None:
            checkpoint(directory_operation, "after")
    except OSError as primary_error:
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                leftover = on_leftover(temporary_name) if on_leftover is not None else temporary_name
                _raise_with_cleanup(
                    primary_error,
                    [_cleanup_record("unlink", leftover, cleanup_error, unconfirmed=True)],
                    [leftover],
                )
        raise primary_error


def _atomic_write(
    path: Path,
    data: bytes,
    mode: int,
    owner: tuple[int, int] | None = None,
    *,
    checkpoint: Any = None,
    replace_operation: str = "publish_replace",
    directory_operation: str = "publish_directory_fsync",
    on_replaced: Any = None,
    on_leftover: Any = None,
    logical_path: str | None = None,
) -> None:
    directory_fd, target_name = _open_parent_nofollow(path, logical_path)
    primary_error: Exception | None = None
    def describe_temp(name: str) -> str:
        if logical_path is None:
            return str(path.parent / name)
        return str(Path(logical_path).parent / name)
    try:
        try:
            _atomic_write_at(
                directory_fd, target_name, data, mode, owner=owner,
                checkpoint=checkpoint, replace_operation=replace_operation,
                directory_operation=directory_operation, on_replaced=on_replaced,
                on_leftover=on_leftover, temp_resource=describe_temp,
            )
        except (PolicyError, OSError) as error:
            primary_error = error
    finally:
        fd, directory_fd = directory_fd, -1
        close_resource = str(Path(logical_path).parent) if logical_path is not None else str(path.parent)
        close_error = _close_once(fd, close_resource)
    if primary_error is not None:
        _raise_with_cleanup(primary_error, [] if close_error is None else [close_error])
    if close_error is not None:
        _raise_with_cleanup(OSError(close_error["errno"], close_error["message"]), [])


def _open_directory_at(parent_fd: int, name: str) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)


def _validate_state_directory(host: Any, fd: int, logical: str, *, private: bool) -> None:
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or host.state_uid(logical, info.st_uid) != 0:
        raise PolicyError(f"unsafe private-state directory: {logical}")
    if private:
        if mode != 0o700:
            raise PolicyError(f"private-state directory is not mode 0700: {logical}")
    elif mode & 0o022:
        raise PolicyError(f"private-state parent is writable by non-root: {logical}")


class _PrivateState:
    """Descriptor-relative handle for the fixed private state directory."""

    def __init__(self, host: Any, directory_fd: int, lock_fd: int) -> None:
        self.host = host
        self.directory_fd: int | None = directory_fd
        self.lock_fd: int | None = lock_fd

    @classmethod
    def open(cls, root: Path, host: Any) -> "_PrivateState":
        current: int | None = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        current_resource = str(root)
        lock_fd: int | None = None
        logical = ""
        try:
            for name in ("var", "lib"):
                assert current is not None
                next_fd = _open_directory_at(current, name)
                old_fd, current = current, None
                close_error = _close_once(old_fd, current_resource)
                if close_error is not None:
                    next_error = _close_once(next_fd, logical + "/" + name)
                    _raise_with_cleanup(
                        OSError(close_error["errno"], close_error["message"]),
                        [] if next_error is None else [next_error],
                    )
                current = next_fd
                logical += "/" + name
                current_resource = logical
                _validate_state_directory(host, current, logical, private=False)
            for name in ("detection-engineering", "stock-log-access"):
                logical += "/" + name
                assert current is not None
                try:
                    os.mkdir(name, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                next_fd = _open_directory_at(current, name)
                old_fd, current = current, None
                close_error = _close_once(old_fd, current_resource)
                if close_error is not None:
                    next_error = _close_once(next_fd, logical)
                    _raise_with_cleanup(
                        OSError(close_error["errno"], close_error["message"]),
                        [] if next_error is None else [next_error],
                    )
                current = next_fd
                current_resource = logical
                _validate_state_directory(host, current, logical, private=True)
            assert current is not None
            try:
                lock_fd = os.open(
                    "lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600, dir_fd=current,
                )
                os.fchmod(lock_fd, 0o600)
            except FileExistsError:
                lock_fd = os.open("lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
            lock_info = os.fstat(lock_fd)
            lock_logical = LOCK_PATH
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
                    stat.S_IMODE(lock_info.st_mode) != 0o600 or
                    host.state_uid(lock_logical, lock_info.st_uid) != 0):
                raise PolicyError("unsafe private-state lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            state = cls(host, current, lock_fd)
            state._validate_marker_if_present()
            current = None
            lock_fd = None
            return state
        except (PolicyError, OSError) as primary:
            cleanup_errors: list[dict[str, Any]] = []
            if lock_fd is not None:
                fd, lock_fd = lock_fd, None
                error = _close_once(fd, LOCK_PATH)
                if error is not None:
                    cleanup_errors.append(error)
            if current is not None:
                fd, current = current, None
                error = _close_once(fd, current_resource)
                if error is not None:
                    cleanup_errors.append(error)
            _raise_with_cleanup(primary, cleanup_errors)
            raise AssertionError("unreachable")

    def _validate_marker_if_present(self) -> None:
        assert self.directory_fd is not None
        try:
            fd = os.open("applied.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.directory_fd)
        except FileNotFoundError:
            return
        primary: Exception | None = None
        try:
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        stat.S_IMODE(info.st_mode) != 0o600 or
                        self.host.state_uid(APPLIED_PATH, info.st_uid) != 0):
                    raise PolicyError("unsafe private applied marker")
            except (PolicyError, OSError) as error:
                primary = error
        finally:
            fd_to_close, fd = fd, -1
            close_error = _close_once(fd_to_close, APPLIED_PATH)
        if primary is not None:
            _raise_with_cleanup(primary, [] if close_error is None else [close_error])
        if close_error is not None:
            _raise_with_cleanup(OSError(close_error["errno"], close_error["message"]), [])

    def read_marker(self) -> bytes | None:
        assert self.directory_fd is not None
        try:
            fd = os.open("applied.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.directory_fd)
        except FileNotFoundError:
            return None
        primary: Exception | None = None
        data = bytearray()
        try:
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        stat.S_IMODE(info.st_mode) != 0o600 or
                        self.host.state_uid(APPLIED_PATH, info.st_uid) != 0):
                    raise PolicyError("unsafe private applied marker")
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except (PolicyError, OSError) as error:
                primary = error
        finally:
            fd_to_close, fd = fd, -1
            close_error = _close_once(fd_to_close, APPLIED_PATH)
        if primary is not None:
            _raise_with_cleanup(primary, [] if close_error is None else [close_error])
        if close_error is not None:
            _raise_with_cleanup(OSError(close_error["errno"], close_error["message"]), [])
        return bytes(data)

    def unlink_marker(self) -> None:
        assert self.directory_fd is not None
        os.unlink("applied.json", dir_fd=self.directory_fd)

    def create_candidate(self, data: bytes) -> tuple[str, Path]:
        assert self.directory_fd is not None
        name = "candidate-" + secrets.token_hex(12)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self.directory_fd)
        primary_error: OSError | None = None
        try:
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                primary_error = exc
        finally:
            fd_to_close, fd = fd, -1
            close_error = _close_once(fd_to_close, STATE_DIRECTORY + "/" + name)
        if primary_error is not None:
            cleanup_errors = [] if close_error is None else [close_error]
            changed_paths: list[str] = []
            try:
                os.unlink(name, dir_fd=self.directory_fd)
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                logical = STATE_DIRECTORY + "/" + name
                cleanup_errors.append(_cleanup_record("unlink", logical, cleanup_error, unconfirmed=True))
                changed_paths.append(logical)
            _raise_with_cleanup(primary_error, cleanup_errors, changed_paths)
        if close_error is not None:
            primary = OSError(close_error["errno"], close_error["message"])
            cleanup_errors = []
            changed_paths = []
            try:
                os.unlink(name, dir_fd=self.directory_fd)
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                logical = STATE_DIRECTORY + "/" + name
                cleanup_errors.append(_cleanup_record("unlink", logical, cleanup_error, unconfirmed=True))
                changed_paths.append(logical)
            _raise_with_cleanup(primary, cleanup_errors, changed_paths)
        return name, Path(f"/proc/{os.getpid()}/fd/{self.directory_fd}/{name}")

    def write_marker(self, data: bytes, host: Any, on_replaced: Any, on_leftover: Any) -> None:
        assert self.directory_fd is not None
        owner = (0, 0) if isinstance(host, NativeHost) else None
        _atomic_write_at(
            self.directory_fd, "applied.json", data, 0o600, owner=owner,
            checkpoint=host.checkpoint, replace_operation="marker_replace",
            directory_operation="marker_directory_fsync", on_replaced=on_replaced,
            on_leftover=on_leftover,
            temp_resource=lambda name: STATE_DIRECTORY + "/" + name,
        )

    def sync(self) -> None:
        assert self.directory_fd is not None
        os.fsync(self.directory_fd)

    def remove(self, name: str) -> None:
        assert self.directory_fd is not None
        try:
            os.unlink(name, dir_fd=self.directory_fd)
        except FileNotFoundError:
            pass

    def close(self) -> list[dict[str, Any]]:
        errors: list[dict[str, Any]] = []
        if self.lock_fd is not None:
            fd, self.lock_fd = self.lock_fd, None
            error = _close_once(fd, LOCK_PATH)
            if error is not None:
                errors.append(error)
        if self.directory_fd is not None:
            fd, self.directory_fd = self.directory_fd, None
            error = _close_once(fd, STATE_DIRECTORY)
            if error is not None:
                errors.append(error)
        return errors


def _marker_digest(candidate: bytes, profile: Any, reader: str, identity: Any) -> str:
    payload = {
        "candidate": _sha256(candidate), "profile": profile.fingerprint,
        "reader": reader, "uid": identity.uid, "gid": identity.gid,
    }
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def run(argv: list[str] | None = None, *, host: Any = None) -> dict[str, Any]:
    args = _arguments(argv)
    host = NativeHost() if host is None else host
    root = Path(args.root)
    stage = "preflight"
    operational_stage = "preflight"
    operational_error: str | None = None
    changed_paths: list[str] = []
    cleanup_errors: list[dict[str, Any]] = []
    producer_active: bool | None = None
    state: _PrivateState | None = None
    candidate_name: str | None = None
    def record_changed(path: str) -> None:
        if path not in changed_paths:
            changed_paths.append(path)
    def record_expected_error(error: Exception) -> None:
        nonlocal operational_stage, operational_error
        primary = error.primary if isinstance(error, _OwnedOperationError) else error
        operational_stage = stage
        operational_error = str(primary)
        if isinstance(error, _OwnedOperationError):
            for path in error.changed_paths:
                record_changed(path)
            if error.cleanup_errors:
                cleanup_errors.extend(error.cleanup_errors)
    try:
        if isinstance(host, NativeHost) and root.resolve() != Path("/"):
            raise PolicyError("native adapter does not operate on an alternate root")
        state = _PrivateState.open(root, host)
        for package in ("rsyslog", "logrotate"):
            if not host.package_installed(package, args.dpkg_query):
                raise PolicyError(f"required package is not installed: {package}")
        user = host.lookup_user(args.reader, args.getent)
        group = host.lookup_group(args.reader, args.getent)
        root_group = host.lookup_group("root", args.getent)
        adm_group = host.lookup_group("adm", args.getent)
        if None in (user, group, root_group, adm_group):
            raise PolicyError("required account identity is missing")
        if user.uid == 0 or user.gid == 0 or group.gid == 0 or user.gid != group.gid:
            raise PolicyError("reader is not a nonroot package identity")
        if group.gid in {root_group.gid, adm_group.gid}:
            raise PolicyError("reader aliases an administrative group")
        profile = validate_profile(root, args.profile_dir)
        if profile.generated_reader not in (None, args.reader):
            raise PolicyError("existing generated configuration belongs to another reader")
        current_config = _physical(root, RSYSLOG_PATH).read_bytes()
        original = _exact_original(Path(args.profile_dir))
        candidate = render_candidate(original if profile.source_kind == "original" else current_config, args.reader)
        source_facts = {
            logical: _safe_source(host, logical, _physical(root, logical), {adm_group.gid, group.gid})
            for logical in CANONICAL
        }
        if len({(facts.dev, facts.ino) for facts in source_facts.values()}) != len(CANONICAL):
            raise PolicyError("canonical sources share an inode")
        config_facts: dict[str, Any] = {}
        for logical in profile.snapshot:
            config_facts[logical] = _safe_config(host, logical, _physical(root, logical))
        if len({(facts.dev, facts.ino) for facts in config_facts.values()}) != len(config_facts):
            raise PolicyError("supported configuration targets share an inode")
        configured_facts = config_facts[RSYSLOG_PATH]
        observation = host.observe_producer(args.systemctl, args.rsyslogd)
        producer_active = observation.active
        if observation.active is not True or not observation.identity_valid:
            raise PolicyError("producer is not fully identity-validated active")
        candidate_name, candidate_temp = state.create_candidate(candidate)
        if not host.validate_candidate(candidate_temp, args.rsyslogd, args.runuser, args.reader):
            raise PolicyError("native candidate validation failed")
        host.checkpoint("snapshot_recheck", "before")
        rechecked = validate_profile(root, args.profile_dir)
        if rechecked.snapshot != profile.snapshot:
            raise PolicyError("effective configuration changed during preflight")
        for logical, before in source_facts.items():
            after = _safe_source(host, logical, _physical(root, logical), {adm_group.gid, group.gid})
            if (before.dev, before.ino, before.uid, before.gid, before.mode) != (after.dev, after.ino, after.uid, after.gid, after.mode):
                raise PolicyError("canonical source changed during preflight")
        for logical, before in config_facts.items():
            after = _safe_config(host, logical, _physical(root, logical))
            if (before.dev, before.ino, before.uid, before.gid, before.mode) != (after.dev, after.ino, after.uid, after.gid, after.mode):
                raise PolicyError("supported configuration object changed during preflight")
        second_observation = host.observe_producer(args.systemctl, args.rsyslogd)
        producer_active = second_observation.active
        if (second_observation.active is True and second_observation.identity_valid and
                second_observation.start_identity != observation.start_identity):
            producer_active = None
            raise PolicyError("producer identity changed during preflight")
        if second_observation.active is not True or not second_observation.identity_valid:
            raise PolicyError("producer identity changed during preflight")

        desired_digest = _marker_digest(candidate, profile, args.reader, user)
        marker_valid = False
        try:
            marker_bytes = state.read_marker()
            if marker_bytes is None:
                raise FileNotFoundError
            marker = json.loads(marker_bytes.decode("utf-8"))
            marker_valid = marker == {"schema": 1, "digest": desired_digest}
        except (OSError, ValueError):
            pass
        config_changed = current_config != candidate
        requires_application = (
            config_changed or not marker_valid or
            any(source_facts[path].gid != group.gid for path in CANONICAL)
        )
        stage = "invalidate_applied"
        host.checkpoint(stage, "before")
        if state.read_marker() is not None and requires_application:
            state.unlink_marker()
            record_changed(APPLIED_PATH)
        if requires_application:
            # This is also required when the marker is already absent: a prior
            # attempt may have unlinked it but failed its durability barrier.
            state.sync()
        host.checkpoint(stage, "after")

        for logical, operation in zip(CANONICAL, ("group_auth", "group_syslog")):
            stage = operation
            host.checkpoint(stage, "before")
            facts = host.file_facts(logical, _physical(root, logical))
            if facts is None or not _same_file_facts(facts, source_facts[logical]):
                raise PolicyError("canonical source identity changed before group update")
            if facts.gid != group.gid:
                try:
                    host.set_group(logical, _physical(root, logical), group.gid, source_facts[logical])
                except (PolicyError, OSError):
                    after_error = host.file_facts(logical, _physical(root, logical))
                    if (after_error is not None and after_error.dev == source_facts[logical].dev and
                            after_error.ino == source_facts[logical].ino and after_error.gid == group.gid):
                        record_changed(logical)
                    raise
                record_changed(logical)
            host.checkpoint(stage, "after")

        stage = "publish_config"
        host.checkpoint(stage, "before")
        if config_changed:
            owner = (configured_facts.uid, configured_facts.gid) if isinstance(host, NativeHost) else None
            def config_replaced() -> None:
                record_changed(RSYSLOG_PATH)
                host.after_publish(RSYSLOG_PATH, _physical(root, RSYSLOG_PATH))
            def config_leftover(name: str) -> str:
                logical = str(Path(RSYSLOG_PATH).parent / name)
                record_changed(logical)
                return logical
            _atomic_write(
                _physical(root, RSYSLOG_PATH), candidate, configured_facts.mode, owner,
                checkpoint=host.checkpoint, on_replaced=config_replaced,
                on_leftover=config_leftover,
                logical_path=RSYSLOG_PATH,
            )
        host.checkpoint(stage, "after")

        if config_changed or not marker_valid:
            stage = "restart"
            host.checkpoint(stage, "before")
            restarted = host.restart_producer(args.systemctl)
            host.checkpoint(stage, "after")
            if not restarted:
                failed_observation = host.observe_producer(args.systemctl, args.rsyslogd)
                producer_active = failed_observation.active
                raise PolicyError("producer restart failed")

        stage = "verify"
        final_observation = host.observe_producer(args.systemctl, args.rsyslogd)
        producer_active = final_observation.active
        if final_observation.active is not True or not final_observation.identity_valid:
            raise PolicyError("producer identity invalid after application")
        for logical in CANONICAL:
            facts = _safe_source(host, logical, _physical(root, logical), {group.gid})
            if facts.gid != group.gid or not host.reader_can_read(
                    logical, _physical(root, logical), user.uid, group.gid, args.runuser, args.reader):
                raise PolicyError("reader cannot read canonical source after application")

        stage = "write_applied"
        host.checkpoint(stage, "before")
        marker_data = (json.dumps({"schema": 1, "digest": desired_digest}, sort_keys=True) + "\n").encode()
        existing = state.read_marker()
        if existing != marker_data:
            marker_replaced = False
            def marker_did_replace() -> None:
                nonlocal marker_replaced
                marker_replaced = True
                record_changed(APPLIED_PATH)
            def marker_leftover(name: str) -> str:
                logical = STATE_DIRECTORY + "/" + name
                record_changed(logical)
                return logical
            try:
                state.write_marker(marker_data, host, marker_did_replace, marker_leftover)
            except (PolicyError, OSError) as publication_error:
                if marker_replaced:
                    cleanup_errors: list[dict[str, Any]] = []
                    try:
                        state.unlink_marker()
                    except OSError as cleanup_error:
                        cleanup_errors.append(_cleanup_record("unlink", APPLIED_PATH, cleanup_error, unconfirmed=True))
                    try:
                        state.sync()
                    except OSError as cleanup_error:
                        cleanup_errors.append(_cleanup_record("fsync", STATE_DIRECTORY, cleanup_error))
                    _raise_with_cleanup(publication_error, cleanup_errors)
                raise publication_error
        host.checkpoint(stage, "after")
        operational_stage = "complete"
    except (PolicyError, OSError) as exc:
        record_expected_error(exc)
    finally:
        if state is not None:
            if candidate_name is not None:
                try:
                    state.remove(candidate_name)
                except OSError as cleanup_error:
                    logical = STATE_DIRECTORY + "/" + candidate_name
                    record_changed(logical)
                    cleanup_errors.append(
                        _cleanup_record("unlink", logical, cleanup_error, unconfirmed=True)
                    )
            cleanup_errors.extend(state.close())
    final_stage = operational_stage
    final_error = operational_error
    if cleanup_errors and operational_stage == "complete":
        final_stage = "cleanup"
        final_error = (
                "operational application completed but private cleanup failed; "
                "applied marker retained"
            )
    result: dict[str, Any] = {
        "changed": bool(changed_paths),
        "stage": final_stage,
        "changed_paths": changed_paths,
        "producer_active": producer_active,
    }
    if final_error is not None:
        result["error"] = final_error
    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors
    return result


def main(argv: list[str] | None = None, *, host: Any = None) -> int:
    result = run(argv, host=host)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["stage"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
