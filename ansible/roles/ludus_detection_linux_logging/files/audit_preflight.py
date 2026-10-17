#!/usr/bin/env python3
"""Refuse active audit plugins outside the reviewed sanitizer."""
import argparse
import os
import re
import sys
from pathlib import Path


def settings(path):
    result = {}
    if not path.exists():
        return result
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def rooted(root, path):
    return root / path.lstrip("/")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--auditd-config", required=True)
    parser.add_argument("--allowed-name", required=True)
    parser.add_argument("--allowed-path", required=True)
    parser.add_argument("--allowed-args", required=True)
    args = parser.parse_args()
    root = Path(args.root or "/")
    audit = settings(rooted(root, args.auditd_config))
    plugin_dir = rooted(root, audit.get("plugin_dir", "/etc/audit/plugins.d"))
    if plugin_dir.exists():
        eligible = re.compile(r"^[^.]+\.conf$")
        for entry in plugin_dir.iterdir():
            if entry.is_symlink() or not entry.is_file() or not eligible.fullmatch(entry.name):
                continue
            config = settings(entry)
            if config.get("active", "no").lower() != "yes":
                continue
            if entry.name != args.allowed_name:
                raise ValueError(f"unreviewed active audit plugin: {entry}")
            expected = {
                "active": "yes",
                "direction": "out",
                "path": args.allowed_path,
                "type": "always",
                "args": args.allowed_args,
                "format": "string",
            }
            if any(config.get(key) != value for key, value in expected.items()):
                raise ValueError(f"reviewed audit plugin has unsafe effective configuration: {entry}")
    log_file = rooted(root, audit.get("log_file", "/var/log/audit/audit.log"))
    for raw_sink in log_file.parent.glob(log_file.name + "*"):
        if raw_sink.is_file() and raw_sink.stat().st_size:
            raise ValueError(f"existing raw audit durable sink requires operator disposition: {raw_sink}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
