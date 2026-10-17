#!/usr/bin/env python3
"""Race-bounded policy-rc.d capture, publication, and restoration."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import stat
from pathlib import Path


AT_FDCWD = -100
RENAME_NOREPLACE = 1


def rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically rename *source* only when *destination* is absent."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise RuntimeError("renameat2(RENAME_NOREPLACE) is unavailable")
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def metadata(path: Path) -> dict[str, object]:
    info = path.lstat()
    kind = "regular" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "other"
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "regular" else None
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "kind": kind,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "sha256": digest,
    }


def same_object(left: dict[str, object], right: dict[str, object]) -> bool:
    return left == right


def write_state(path: Path, value: dict[str, object], *, exclusive: bool = False) -> None:
    payload = json.dumps(value, sort_keys=True).encode()
    if exclusive:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def validate_private_directory(directory: Path, public: Path, expected_uid: int) -> None:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != expected_uid:
        raise RuntimeError("transaction directory must be an expected-owner 0700 directory")
    if info.st_dev != public.parent.stat().st_dev:
        raise RuntimeError("transaction directory must share the public policy filesystem")


def begin(public: Path, directory: Path, staged: Path, state_path: Path, expected_uid: int) -> None:
    validate_private_directory(directory, public, expected_uid)
    original = directory / "original-policy"
    captured = directory / "captured-public"
    if os.path.lexists(state_path) or os.path.lexists(original) or os.path.lexists(captured):
        raise RuntimeError("stale policy transaction requires explicit disposition")
    staged_meta = metadata(staged)
    if staged_meta["kind"] != "regular" or staged_meta["uid"] != expected_uid or staged_meta["mode"] != 0o755:
        raise RuntimeError("staged wrapper must be an expected-owner regular 0755 file")
    state_value: dict[str, object] = {
        "schema_version": 1,
        "original": None,
        "wrapper": staged_meta,
    }
    write_state(state_path, state_value, exclusive=True)
    if os.path.lexists(public):
        rename_noreplace(public, original)
        state_value["original"] = metadata(original)
        write_state(state_path, state_value)
        original_meta = state_value["original"]
        if not isinstance(original_meta, dict) or original_meta["kind"] != "regular":
            raise RuntimeError("captured original policy is not a regular file")
        if original_meta["uid"] != expected_uid or not (int(original_meta["mode"]) & stat.S_IXUSR):
            raise RuntimeError("captured original policy has unsafe ownership or mode")
    rename_noreplace(staged, public)
    if not same_object(metadata(public), staged_meta):
        raise RuntimeError("published wrapper identity changed")


def cleanup(public: Path, directory: Path, staged: Path, state_path: Path, expected_uid: int) -> None:
    validate_private_directory(directory, public, expected_uid)
    if not os.path.lexists(state_path):
        return
    state_value = json.loads(state_path.read_text(encoding="utf-8"))
    if set(state_value) != {"schema_version", "original", "wrapper"} or state_value["schema_version"] != 1:
        raise RuntimeError("malformed private policy transaction state")
    original = directory / "original-policy"
    captured = directory / "captured-public"
    if os.path.lexists(captured):
        raise RuntimeError("stale captured public policy requires explicit disposition")
    if os.path.lexists(public):
        rename_noreplace(public, captured)
    if os.path.lexists(captured):
        captured_meta = metadata(captured)
        wrapper_meta = state_value["wrapper"]
        if not isinstance(wrapper_meta, dict) or not same_object(captured_meta, wrapper_meta):
            try:
                rename_noreplace(captured, public)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise
            raise RuntimeError("foreign public policy preserved; original remains quarantined")
        captured.unlink()
    if os.path.lexists(original):
        recorded_original = state_value["original"]
        if not isinstance(recorded_original, dict) or not same_object(metadata(original), recorded_original):
            raise RuntimeError("quarantined original policy identity changed")
        rename_noreplace(original, public)
    elif state_value["original"] is not None:
        raise RuntimeError("recorded original policy is missing")
    if os.path.lexists(staged):
        if not same_object(metadata(staged), state_value["wrapper"]):
            raise RuntimeError("private staged wrapper identity changed")
        staged.unlink()
    state_path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("begin", "cleanup"))
    parser.add_argument("--public", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--staged", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--expected-uid", required=True, type=int)
    arguments = parser.parse_args()
    operation = begin if arguments.operation == "begin" else cleanup
    operation(arguments.public, arguments.directory, arguments.staged, arguments.state, arguments.expected_uid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
