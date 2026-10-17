#!/usr/bin/env python3
"""Incrementally convert auditd string records to bounded safe JSONL."""
import argparse
import grp
import json
import os
import pwd
import re
import sys

RECORD = re.compile(r"^type=([A-Z0-9_]+) msg=audit\(([^:()]+):(\d+)\):(?:\s.*)?$")
FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
SAFE = {"pid", "ppid", "uid", "auid", "ses", "comm", "exe", "key", "success", "exit", "syscall"}
DROP = {"EXECVE", "PROCTITLE", "EOE"}


def identity(value, database):
    try:
        return int(value)
    except ValueError:
        return database(value)[2]


def safe_record(line):
    match = RECORD.fullmatch(line)
    if not match:
        raise ValueError("malformed audit string record")
    record_type, timestamp, serial = match.groups()
    if record_type in DROP or record_type != "SYSCALL":
        return None
    values = {key: value.strip('"') for key, value in FIELD.findall(line) if key in SAFE}
    for required in ("pid", "uid", "exe", "comm"):
        if required not in values:
            raise ValueError(f"SYSCALL record lacks {required}")
    values.update({"record_type": record_type, "audit_timestamp": timestamp, "audit_serial": serial})
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--owner", default="0")
    parser.add_argument("--group", default="0")
    args = parser.parse_args()
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(args.output, flags, 0o640)
    try:
        os.fchmod(descriptor, 0o640)
        os.fchown(descriptor, identity(args.owner, pwd.getpwnam), identity(args.group, grp.getgrnam))
        with os.fdopen(descriptor, "w", encoding="utf-8", buffering=1) as stream:
            descriptor = -1
            while True:
                raw = sys.stdin.buffer.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    raise ValueError("partial audit record at EOF")
                record = safe_record(raw[:-1].decode("utf-8", errors="strict"))
                if record is not None:
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
                    stream.flush()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"audit sanitizer failed closed: {error}", file=sys.stderr)
        raise SystemExit(2)
