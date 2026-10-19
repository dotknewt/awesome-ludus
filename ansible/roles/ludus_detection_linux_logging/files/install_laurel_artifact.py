#!/usr/bin/env python3
"""Validate and atomically install a checksum-pinned Laurel archive."""
import argparse
import hashlib
import os
from pathlib import Path
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--destination")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    archive = Path(args.archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != args.sha256:
        raise ValueError("Laurel archive checksum changed after download")

    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        selected = None
        seen = set()
        member_types = {}
        for member in members:
            name = member.name
            if "\\" in name or name.startswith("/") or "\x00" in name:
                raise ValueError("archive contains an unsafe member path")
            parts = name.split("/")
            if member.isdir() and parts[-1] == "":
                parts.pop()
            if not parts or any(part in ("", ".", "..") for part in parts):
                raise ValueError("archive contains an unsafe member path")
            canonical = "/".join(parts)
            if canonical in seen:
                raise ValueError("archive contains duplicate member paths")
            seen.add(canonical)
            if not (member.isreg() or member.isdir()):
                raise ValueError("archive contains an unsupported member type")
            member_types[canonical] = member.isdir()
            if canonical == "laurel":
                if not member.isreg():
                    raise ValueError("archive must contain one regular root member named laurel")
                selected = member
        for canonical in member_types:
            parts = canonical.split("/")
            for depth in range(1, len(parts)):
                ancestor = "/".join(parts[:depth])
                if ancestor in member_types and not member_types[ancestor]:
                    raise ValueError("regular member is an ancestor of another archive path")
        if selected is None:
            raise ValueError("archive must contain one regular root member named laurel")
        source = bundle.extractfile(selected)
        if source is None:
            raise ValueError("Laurel archive member is unreadable")
        payload = source.read()
        if len(payload) != selected.size:
            raise ValueError("Laurel archive member is truncated")

    if args.check_only:
        print("OK safe archive")
        return
    if not args.destination:
        raise ValueError("destination is required for installation")
    destination = Path(args.destination)
    if destination.is_file() and destination.read_bytes() == payload:
        if destination.stat().st_mode & 0o777 != 0o755:
            os.chmod(destination, 0o755)
            print("CHANGED mode")
        else:
            print("OK")
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".laurel-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination)
        print("CHANGED content")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    try:
        main()
    except (EOFError, OSError, tarfile.TarError, ValueError) as error:
        raise SystemExit(f"Laurel artifact rejected: {error}")
