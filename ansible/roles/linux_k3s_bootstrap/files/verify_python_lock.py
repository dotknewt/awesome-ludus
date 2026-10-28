"""Compare venv-local distributions with the role's exact requirements lock."""

import importlib.metadata
import json
from pathlib import Path
import re
import sys
import sysconfig


def canonical_name(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def locked_versions(path):
    versions = {}
    pattern = re.compile(r"^([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:[0-9a-f]{64}$")
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid lock entry: {line}")
        versions[canonical_name(match.group(1))] = match.group(2)
    return versions


def local_versions():
    paths = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    return {
        canonical_name(distribution.metadata["Name"]): distribution.version
        for distribution in importlib.metadata.distributions(path=paths)
    }


expected = locked_versions(sys.argv[1])
installed = local_versions()
bootstrap_names = {"pip", "setuptools"}
result = {
    "missing": sorted(set(expected) - set(installed)),
    "mismatched": {
        name: {"expected": expected[name], "actual": installed[name]}
        for name in sorted(set(expected) & set(installed))
        if expected[name] != installed[name]
    },
    "unexpected": sorted(set(installed) - set(expected) - bootstrap_names),
    "bootstrap": {
        name: installed[name]
        for name in sorted(set(installed) & bootstrap_names)
    },
}
print(json.dumps(result, sort_keys=True))
