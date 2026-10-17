#!/usr/bin/env python3
"""Verify one exact primary OpenPGP fingerprint, then write its dearmored keyring."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify_gpg_primary KEY EXPECTED_FINGERPRINT OUTPUT")
    source, expected, output = Path(sys.argv[1]), sys.argv[2].upper(), Path(sys.argv[3])
    shown = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--show-keys", "--fingerprint", str(source)],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    primary_fingerprints: list[str] = []
    awaiting_primary = False
    for line in shown:
        fields = line.split(":")
        record = fields[0]
        if record == "pub":
            awaiting_primary = True
        elif record == "sub":
            awaiting_primary = False
        elif record == "fpr" and awaiting_primary:
            primary_fingerprints.append(fields[9].upper())
            awaiting_primary = False
    if primary_fingerprints != [expected]:
        raise SystemExit("signing key must contain exactly the expected primary fingerprint")
    temporary = output.with_name(output.name + ".tmp")
    temporary.unlink(missing_ok=True)
    subprocess.run(
        ["gpg", "--batch", "--yes", "--dearmor", "--output", str(temporary), str(source)],
        check=True,
    )
    with temporary.open("rb") as stream:
        __import__("os").fsync(stream.fileno())
    temporary.chmod(0o644)
    temporary.replace(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
