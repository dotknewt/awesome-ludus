#!/usr/bin/env python3
"""Require one primary OpenPGP key whose fingerprint exactly matches argv[1]."""

from __future__ import annotations

import sys


def main() -> int:
    expected = sys.argv[1].replace(" ", "").upper()
    primary_fingerprints: list[str] = []
    awaiting_primary_fingerprint = False
    primary_count = 0
    for raw_line in sys.stdin:
        fields = raw_line.rstrip("\n").split(":")
        record = fields[0] if fields else ""
        if record == "pub":
            primary_count += 1
            awaiting_primary_fingerprint = True
        elif record in {"sub", "sec", "ssb"}:
            awaiting_primary_fingerprint = False
        elif record == "fpr" and awaiting_primary_fingerprint:
            if len(fields) <= 9 or not fields[9]:
                return 2
            primary_fingerprints.append(fields[9].upper())
            awaiting_primary_fingerprint = False

    if primary_count != 1 or primary_fingerprints != [expected]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
