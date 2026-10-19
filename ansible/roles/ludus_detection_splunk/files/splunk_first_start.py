#!/usr/bin/env python3
"""Atomic, ownership-aware staging for Splunk's one-use first-start files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path


def _token(path: Path, expected: str) -> None:
    try:
        value, device, inode = expected.split("|", 2)
        expected_device = int(device)
        expected_inode = int(inode)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("first-start lock token is malformed; recover explicitly") from exc
    try:
        current = os.lstat(path)
        actual = path.read_text(encoding="ascii")
    except FileNotFoundError as exc:
        raise RuntimeError("first-start lock is missing; recover explicitly") from exc
    if (
        actual != value
        or not stat.S_ISREG(current.st_mode)
        or current.st_dev != expected_device
        or current.st_ino != expected_inode
    ):
        raise RuntimeError("first-start lock ownership changed; recover explicitly")


def acquire(path: Path) -> str:
    token = secrets.token_hex(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(
            "another or interrupted first-start attempt holds the lock; inspect and recover explicitly"
        ) from exc
    try:
        os.write(fd, token.encode("ascii"))
        os.fsync(fd)
        identity = os.fstat(fd)
    finally:
        os.close(fd)
    print(f"{token}|{identity.st_dev}|{identity.st_ino}")
    return token


def stage(path: Path, lock: Path, token: str, mode: int, owner: str, group: str) -> None:
    _token(lock, token)
    payload = sys.stdin.buffer.read()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".splunk-first-start-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, _uid(owner), _gid(group))
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # link() publishes atomically and fails with EEXIST; unlike copy/rename
        # it cannot replace a file created by another writer after preflight.
        os.link(temporary, path, follow_symlinks=False)
        published = os.lstat(path)
        if not stat.S_ISREG(published.st_mode):
            raise RuntimeError("published first-start path is not a regular file")
        record = {
            "path": str(path),
            "device": published.st_dev,
            "inode": published.st_ino,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        print(json.dumps(record, sort_keys=True))
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def cleanup(record: dict[str, object], lock: Path, token: str) -> None:
    _token(lock, token)
    path = Path(str(record["path"]))
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        # Splunk may naturally consume user-seed.conf during first start.
        return
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != record.get("device")
        or current.st_ino != record.get("inode")
    ):
        raise RuntimeError(f"{path} was replaced; preserved it for explicit first-start recovery")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != record.get("sha256"):
        raise RuntimeError(f"{path} changed; preserved it for explicit first-start recovery")
    os.unlink(path)


def release(path: Path, token: str) -> None:
    _token(path, token)
    path.unlink()


def _uid(name: str) -> int:
    import pwd

    return pwd.getpwnam(name).pw_uid


def _gid(name: str) -> int:
    import grp

    return grp.getgrnam(name).gr_gid


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    acquire_parser = sub.add_parser("acquire")
    acquire_parser.add_argument("--lock", type=Path, required=True)
    stage_parser = sub.add_parser("stage")
    stage_parser.add_argument("--path", type=Path, required=True)
    stage_parser.add_argument("--lock", type=Path, required=True)
    stage_parser.add_argument("--token", required=True)
    stage_parser.add_argument("--mode", type=lambda value: int(value, 8), required=True)
    stage_parser.add_argument("--owner", required=True)
    stage_parser.add_argument("--group", required=True)
    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("--lock", type=Path, required=True)
    cleanup_parser.add_argument("--token", required=True)
    cleanup_parser.add_argument("--record", required=True)
    release_parser = sub.add_parser("release")
    release_parser.add_argument("--lock", type=Path, required=True)
    release_parser.add_argument("--token", required=True)
    args = parser.parse_args()
    try:
        if args.action == "acquire":
            acquire(args.lock)
        elif args.action == "stage":
            stage(args.path, args.lock, args.token, args.mode, args.owner, args.group)
        elif args.action == "cleanup":
            cleanup(json.loads(args.record), args.lock, args.token)
        else:
            release(args.lock, args.token)
    except (OSError, RuntimeError, KeyError, ValueError) as exc:
        print(f"first-start ownership failure: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
