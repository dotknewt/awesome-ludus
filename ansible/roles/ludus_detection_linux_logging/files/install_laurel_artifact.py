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
        if len(members) != 1 or members[0].name != "laurel" or not members[0].isreg():
            raise ValueError("archive must contain exactly one regular root member named laurel")
        source = bundle.extractfile(members[0])
        if source is None:
            raise ValueError("Laurel archive member is unreadable")
        payload = source.read()

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
    except (OSError, tarfile.TarError, ValueError) as error:
        raise SystemExit(f"Laurel artifact rejected: {error}")
