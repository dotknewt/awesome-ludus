#!/usr/bin/env python3
"""Install one checksum-bound raw or tar.gz runtime artifact safely."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile


def fail(message: str) -> None:
    raise SystemExit(message)


def safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def stream_member(archive: Path, member_name: str, destination) -> None:
    seen: set[str] = set()
    selected = None
    with tarfile.open(archive, mode="r:gz") as bundle:
        for member in bundle.getmembers():
            if not safe_name(member.name) or member.name in seen:
                fail("unsafe or duplicate tar member")
            seen.add(member.name)
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                fail("links and special tar members are forbidden")
            if member.name == member_name:
                if not member.isfile() or selected is not None:
                    fail("selected member must be one unique regular file")
                selected = member
        if selected is None:
            fail("selected member is absent")
        source = bundle.extractfile(selected)
        if source is None:
            fail("selected member cannot be streamed")
        while chunk := source.read(1024 * 1024):
            destination.write(chunk)


def main() -> int:
    if len(sys.argv) != 8:
        fail("usage: installer TOOL ARTIFACT SHA FORMAT MEMBER DEST MODE")
    _, tool, artifact_text, expected_sha, format_name, member_name, destination_text, mode_text = sys.argv
    artifact = Path(artifact_text)
    destination = Path(destination_text)
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_sha:
        fail("artifact checksum differs from its verified layout binding")
    if format_name not in {"raw", "tar.gz"}:
        fail("unsupported artifact format")
    if format_name == "raw" and member_name != "-":
        fail("raw artifacts require a null member")
    if format_name == "tar.gz" and (member_name == "-" or not safe_name(member_name)):
        fail("tar.gz artifacts require one safe relative member")

    destination.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(destination):
        metadata = destination.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            fail("existing destination must be a regular non-symlink file")
    descriptor, temporary_text = tempfile.mkstemp(prefix=f".{tool}-", dir=destination.parent)
    temporary = Path(temporary_text)
    try:
        with os.fdopen(descriptor, "wb") as output:
            if format_name == "raw":
                with artifact.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
            else:
                stream_member(artifact, member_name, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, int(mode_text, 8))
        current = destination.read_bytes() if destination.exists() else None
        installed = temporary.read_bytes()
        if current == installed and stat.S_IMODE(destination.stat().st_mode) == int(mode_text, 8):
            return 10
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return 0
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
