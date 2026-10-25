#!/usr/bin/env python3
"""Capture sanitized local Ansible evidence; never performs deployment actions."""
import argparse
import json
import os
import re
import stat
import sys

from deployment_evidence import EvidenceError, collect_evidence

MAX_FILE = 256_000
_RANGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)


class FixedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise EvidenceError("arguments")


def _strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError

    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)


def _open_parent(path):
    """Open all parent directories one component at a time without symlinks."""
    if not path or "\x00" in path:
        raise ValueError
    absolute = os.path.isabs(path)
    parts = [part for part in path.split(os.sep) if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ValueError
    leaf = parts.pop()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(os.sep if absolute else ".", flags)
    try:
        for component in parts:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, leaf
    except Exception:
        os.close(fd)
        raise


def _read_local_json(path):
    parent_fd, leaf = _open_parent(path)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(leaf, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError
        chunks = []
        total = 0
        while total <= MAX_FILE:
            chunk = os.read(fd, min(65536, MAX_FILE + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_FILE:
            raise ValueError
        return _strict_json(b"".join(chunks).decode("utf-8"))
    finally:
        os.close(fd)


def _persist(output_path, evidence):
    parent_fd, leaf = _open_parent(output_path)
    try:
        os.mkdir(leaf, 0o700, dir_fd=parent_fd)
        created = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        directory_fd = os.open(leaf, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            opened = os.fstat(directory_fd)
            if not stat.S_ISDIR(created.st_mode) or (created.st_dev, created.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError
            os.fchmod(directory_fd, 0o700)
        except Exception:
            os.close(directory_fd)
            raise
    finally:
        os.close(parent_fd)
    try:
        temporary = ".evidence.tmp"
        target = "evidence.json"
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        published = False
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            readback = bytearray()
            while len(readback) <= len(encoded):
                chunk = os.read(fd, min(65536, len(encoded) + 1 - len(readback)))
                if not chunk:
                    break
                readback.extend(chunk)
            if bytes(readback) != encoded or _strict_json(readback.decode("ascii")) != evidence:
                raise ValueError
            os.link(temporary, target, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            published = True
            os.fsync(directory_fd)
            os.unlink(temporary, dir_fd=directory_fd)
        except Exception:
            if published:
                os.unlink(target, dir_fd=directory_fd)
            raise
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def main(argv=None):
    parser = FixedArgumentParser(
        description=("Sanitize already-collected Ansible default-callback text. "
                     "Use a private Ludus status JSON and reviewed exact host/task allowlist. "
                     "Matching status does not verify supplied log attribution; no remote action is performed."))
    parser.add_argument("--range", required=True)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--allowlist", required=True)
    parser.add_argument("--output", required=True)
    try:
        args = parser.parse_args(argv)
        if not _RANGE.fullmatch(args.range):
            raise EvidenceError("arguments")
        status = _read_local_json(args.status)
        allowlist = _read_local_json(args.allowlist)
        result = collect_evidence(sys.stdin, status, allowlist,
                                  range_id=args.range, deployment=args.deployment)
        _persist(args.output, result)
        incomplete = bool(result["issues"]) or any(row["outcome"] == "unknown" for row in result["tasks"])
        print("capture: incomplete" if incomplete else "capture: complete")
        return 3 if incomplete else 0
    except SystemExit as exc:
        # argparse help is the only ordinary SystemExit path.
        return int(exc.code)
    except Exception:
        print("capture: error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
