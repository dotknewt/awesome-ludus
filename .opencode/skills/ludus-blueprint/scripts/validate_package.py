"""Read-only source-package checks; intentionally does not validate range schema."""

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required; install it in your Python environment.")


def load_mapping(path):
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a YAML mapping")
    return value


def check(root, directory):
    errors = []
    base = (root / "blueprints").resolve()
    package = (base / directory).resolve()
    if package == base or not package.is_relative_to(base):
        return ["blueprint directory must be inside source/blueprints"]
    try:
        manifest = load_mapping(package / "blueprint.yml")
    except (OSError, ValueError, yaml.YAMLError) as error:
        return [str(error)]

    if type(manifest.get("manifest_version")) is not int or manifest["manifest_version"] != 1:
        errors.append("manifest_version: expected supported integer version 1")
    for key in ("id", "name", "description", "version", "config"):
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            errors.append(f"{key}: expected nonempty string (authoring profile)")
    if isinstance(manifest.get("id"), str) and not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_-]*(?:/[A-Za-z0-9_-]+){0,2}", manifest["id"]
    ):
        errors.append("id: invalid blueprint identifier")
    if "tags" in manifest and (
        not isinstance(manifest["tags"], list)
        or any(not isinstance(tag, str) for tag in manifest["tags"])
    ):
        errors.append("tags: expected a list of strings")
    if "min_ludus_version" in manifest and not isinstance(manifest["min_ludus_version"], str):
        errors.append("min_ludus_version: expected a string")

    config = manifest.get("config")
    if isinstance(config, str) and config.strip():
        target = (package / config).resolve()
        if Path(config).is_absolute() or not target.is_relative_to(package):
            errors.append("config: must resolve inside the blueprint directory")
        elif not target.is_file():
            errors.append(f"config: missing file {config}")
    if not (package / "README.md").is_file():
        errors.append("README.md: required by the skill authoring profile")
    for folder, destination in (
        ("roles", "ansible/roles"), ("collections", "ansible/collections"),
        ("templates", "templates"),
    ):
        if (package / folder).exists():
            errors.append(f"{folder}: place distributable assets at source-root {destination}")

    requirements = package / "requirements.yml"
    if requirements.exists():
        try:
            declarations = load_mapping(requirements)
            for kind in ("roles", "collections", "subscription_roles"):
                entries = declarations.get(kind, [])
                if not isinstance(entries, list):
                    errors.append(f"requirements.yml {kind}: expected a list")
                    continue
                for entry in entries:
                    name = entry.get("name") if isinstance(entry, dict) else entry
                    if not isinstance(name, str) or not name.strip():
                        errors.append(f"requirements.yml {kind}: each entry needs a name")
        except (OSError, ValueError, yaml.YAMLError) as error:
            errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("blueprint_directory", help="path relative to source-root/blueprints")
    args = parser.parse_args()
    errors = check(args.source_root.resolve(), args.blueprint_directory)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Package checks passed. Range validation, dependency coverage, and runtime checks are separate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
