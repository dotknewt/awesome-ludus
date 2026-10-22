#!/usr/bin/env python3
"""Run available static Ansible/YAML validators without installing anything."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Mapping, Sequence


TOOLS = ("ansible-playbook", "ansible-lint", "yamllint")
PACKAGES = {
    "ansible-playbook": "ansible-core",
    "ansible-lint": "ansible-lint",
    "yamllint": "yamllint",
}
WARNING_STATUS = "PASS WITH WARNINGS — NOT VERIFIED"
ROLE_PLAYBOOKS = (
    Path("ansible/roles/ludus_bridge_promisq/ludus-configure-bridge.yaml"),
)


class InvocationError(ValueError):
    """The requested validation scope is malformed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InvocationError(message)


@dataclass(frozen=True)
class Inventory:
    roles: tuple[Path, ...]
    playbooks: tuple[Path, ...]
    data: tuple[Path, ...]
    syntax_targets: tuple[Path, ...]
    ansible_lint_targets: tuple[Path, ...]
    yaml_targets: tuple[Path, ...]
    coverage_errors: tuple[str, ...]


@dataclass(frozen=True)
class ToolResult:
    tool: str
    executable: str | None
    status: str
    targets: tuple[str, ...]
    detail: str


def _unique(paths: Sequence[Path]) -> tuple[Path, ...]:
    return tuple(dict.fromkeys(paths))


def _path(value: str, root: Path) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else root / candidate


def parse_args(argv: Sequence[str], repo_root: Path | None = None) -> argparse.Namespace:
    root = Path.cwd() if repo_root is None else repo_root
    parser = _Parser(description=__doc__)
    parser.add_argument("--role", action="append", default=[])
    parser.add_argument("--playbook", action="append", default=[])
    parser.add_argument("--data", action="append", default=[])
    parser.add_argument("--coverage-gap", action="append", default=[])
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(list(argv))

    explicit = args.role or args.playbook or args.data or args.coverage_gap
    if args.all and explicit:
        raise InvocationError("--all cannot be combined with explicit scope options")
    if not args.all and not explicit:
        raise InvocationError("supply --role, --playbook, --data, --coverage-gap, or --all")

    for field, must_be_dir in (("role", True), ("playbook", False), ("data", False)):
        checked: list[Path] = []
        for raw in getattr(args, field):
            path = _path(raw, root)
            if not path.exists():
                raise InvocationError(f"{field} path does not exist: {path}")
            if must_be_dir and not path.is_dir():
                raise InvocationError(f"role path is not a directory: {path}")
            if not must_be_dir and not path.is_file():
                raise InvocationError(f"{field} path is not a file: {path}")
            if not must_be_dir and path.suffix.lower() not in (".yml", ".yaml"):
                raise InvocationError(f"{field} path is not YAML: {path}")
            checked.append(path)
        setattr(args, field, checked)
    if any(not gap.strip() for gap in args.coverage_gap):
        raise InvocationError("coverage gaps must not be empty")
    return args


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _yaml_files(directory: Path, containment_root: Path) -> tuple[Path, ...]:
    if not directory.is_dir() or not _contained(directory, containment_root):
        return ()
    candidates = sorted((*directory.rglob("*.yml"), *directory.rglob("*.yaml")))
    return tuple(path for path in candidates if path.is_file() and _contained(path, containment_root))


def _discover_all(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...], tuple[Path, ...]]:
    roles_root = root / "ansible" / "roles"
    roles = (
        tuple(
            sorted(
                path
                for path in roles_root.iterdir()
                if path.is_dir() and _contained(path, root)
            )
        )
        if roles_root.is_dir()
        else ()
    )

    playbooks = [
        path
        for relative_path in ROLE_PLAYBOOKS
        if (path := root / relative_path).is_file() and _contained(path, root)
    ]
    templates_root = root / "templates"
    if templates_root.is_dir():
        for template in sorted(path for path in templates_root.iterdir() if path.is_dir()):
            playbooks.extend(_yaml_files(template / "ansible", root))

    data: list[Path] = []
    source = root / "source.yml"
    if source.is_file() and _contained(source, root):
        data.append(source)
    data.extend(_yaml_files(root / "ansible" / "collections", root))
    data.extend(_yaml_files(root / "blueprints", root))
    known_root = {"source.yml", ".yamllint.yml", ".yamllint.yaml"}
    root_yaml = sorted((*root.glob("*.yml"), *root.glob("*.yaml")))
    data.extend(
        path
        for path in root_yaml
        if path.name not in known_root and path.is_file() and _contained(path, root)
    )
    return roles, tuple(playbooks), tuple(data)


def build_inventory(args: argparse.Namespace, repo_root: Path | None = None) -> Inventory:
    root = Path.cwd() if repo_root is None else repo_root
    if args.all:
        roles, playbooks, data = _discover_all(root)
    else:
        roles = tuple(args.role)
        playbooks = tuple(args.playbook)
        data = tuple(args.data)

    coverage_errors: list[str] = []
    syntax_targets: list[Path] = []
    yaml_targets: list[Path] = []
    for role in roles:
        harness = role / "tests" / "syntax.yml"
        harness_allowed = not args.all or _contained(harness, root)
        if harness.is_file() and harness_allowed:
            syntax_targets.append(harness)
        else:
            coverage_errors.append(f"missing syntax harness: {harness}")
        if args.all:
            yaml_targets.extend(_yaml_files(role, root))
        else:
            yaml_targets.extend(sorted((*role.rglob("*.yml"), *role.rglob("*.yaml"))))
    coverage_errors.extend(args.coverage_gap)
    syntax_targets.extend(playbooks)
    yaml_targets.extend(playbooks)
    yaml_targets.extend(data)
    return Inventory(
        roles=_unique(roles),
        playbooks=_unique(playbooks),
        data=_unique(data),
        syntax_targets=_unique(syntax_targets),
        ansible_lint_targets=_unique((*roles, *playbooks)),
        yaml_targets=_unique(yaml_targets),
        coverage_errors=tuple(coverage_errors),
    )


def build_commands(
    tool: str, executable: str, inventory: Inventory, repo_root: Path | None = None
) -> tuple[tuple[str, ...], ...]:
    root = Path.cwd() if repo_root is None else repo_root
    if tool == "ansible-playbook":
        return tuple((executable, "--syntax-check", str(target)) for target in inventory.syntax_targets)
    if tool == "ansible-lint":
        if not inventory.ansible_lint_targets:
            return ()
        return (
            (
                executable,
                "--offline",
                "-c",
                str(root / ".ansible-lint"),
                *(str(target) for target in inventory.ansible_lint_targets),
            ),
        )
    if tool == "yamllint":
        if not inventory.yaml_targets:
            return ()
        return (
            (
                executable,
                "-c",
                str(root / ".yamllint.yml"),
                *(str(target) for target in inventory.yaml_targets),
            ),
        )
    raise ValueError(f"unknown tool: {tool}")


def tool_environment(inventory: Inventory, base: Mapping[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    role_parents = tuple(dict.fromkeys(str(role.parent) for role in inventory.roles))
    if role_parents:
        env["ANSIBLE_ROLES_PATH"] = os.pathsep.join(role_parents)
    else:
        env.pop("ANSIBLE_ROLES_PATH", None)
    return env


def result_from_process(
    tool: str,
    executable: str,
    targets: Sequence[str],
    completed: Sequence[subprocess.CompletedProcess[str]],
) -> ToolResult:
    output: list[str] = []
    failed = False
    for process in completed:
        failed = failed or process.returncode != 0
        if process.stdout:
            output.append(process.stdout.rstrip())
        if process.stderr:
            output.append(process.stderr.rstrip())
    summary = f"{len(completed)} check(s); exit status " + ("failed" if failed else "successful")
    detail = "\n".join((summary, *output))
    return ToolResult(tool, executable, "FAIL" if failed else "PASS", tuple(targets), detail)


def run_commands(
    tool: str,
    executable: str,
    commands: Sequence[Sequence[str]],
    targets: Sequence[str],
    env: Mapping[str, str],
) -> ToolResult:
    completed: list[subprocess.CompletedProcess[str]] = []
    try:
        for command in commands:
            completed.append(
                subprocess.run(command, text=True, capture_output=True, check=False, env=dict(env))
            )
    except OSError as error:
        prior = result_from_process(tool, executable, targets, completed)
        detail = f"{prior.detail}\ncould not launch {tool}: {error}"
        return ToolResult(tool, executable, "FAIL", tuple(targets), detail)
    return result_from_process(tool, executable, targets, completed)


def _targets_for(tool: str, inventory: Inventory) -> tuple[str, ...]:
    selected = {
        "ansible-playbook": inventory.syntax_targets,
        "ansible-lint": inventory.ansible_lint_targets,
        "yamllint": inventory.yaml_targets,
    }[tool]
    return tuple(str(path) for path in selected)


def run_tools(inventory: Inventory, root: Path) -> tuple[ToolResult, ...]:
    results: list[ToolResult] = []
    env = tool_environment(inventory)
    for tool in TOOLS:
        targets = _targets_for(tool, inventory)
        executable = shutil.which(tool)
        if executable is None:
            results.append(ToolResult(tool, None, "NOT AVAILABLE", targets, f"{tool} was not found on PATH"))
            continue
        commands = build_commands(tool, executable, inventory, root)
        results.append(run_commands(tool, executable, commands, targets, env))
    return tuple(results)


def aggregate_status(results: Sequence[ToolResult], coverage_errors: Sequence[str]) -> tuple[str, int]:
    if coverage_errors or any(result.status == "FAIL" for result in results):
        return "FAIL", 1
    if any(result.status == "NOT AVAILABLE" for result in results):
        return WARNING_STATUS, 0
    return "PASS", 0


def command_count(tool: str, target_count: int) -> int:
    if tool == "ansible-playbook":
        return target_count
    return int(target_count > 0)


def rerun_command(argv: Sequence[str]) -> str:
    arguments = " ".join(shlex.quote(argument) for argument in argv)
    base = "PATH=\"$PWD/.venv/ansible-validation/bin:$PATH\" python3 "
    base += ".opencode/skills/ansible-validation/scripts/validate.py"
    return f"{base} {arguments}" if arguments else base


def render_report(
    inventory: Inventory, results: Sequence[ToolResult], argv: Sequence[str], overall: str
) -> str:
    lines = ["Static validation", "================="]
    lines.append(f"Roles: {len(inventory.roles)}")
    lines.extend(f"  - {path}" for path in inventory.roles)
    lines.append(f"Playbooks: {len(inventory.playbooks)}")
    lines.extend(f"  - {path}" for path in inventory.playbooks)
    lines.append(f"Data files: {len(inventory.data)}")
    lines.extend(f"  - {path}" for path in inventory.data)
    lines.append(f"Coverage errors: {len(inventory.coverage_errors)}")
    lines.extend(f"  - {error}" for error in inventory.coverage_errors)
    for result in results:
        executable = result.executable or "not found"
        lines.extend(
            (
                "",
                f"{result.tool}: {result.status}",
                f"  executable: {executable}",
                f"  targets: {len(result.targets)}",
                f"  planned commands: {command_count(result.tool, len(result.targets))}",
            )
        )
        inventory_label = "target inventory (UNVERIFIED)" if result.status == "NOT AVAILABLE" else "target inventory"
        lines.append(f"  {inventory_label}:")
        lines.extend(f"    - {target}" for target in result.targets)
        if not result.targets:
            lines.append("    - (none)")
        if result.detail:
            lines.extend(f"  {line}" for line in result.detail.splitlines())

    missing = [PACKAGES[result.tool] for result in results if result.status == "NOT AVAILABLE"]
    if missing:
        lines.extend(
            (
                "",
                "Optional isolated installation (not run):",
                "  python3 -m venv .venv/ansible-validation",
                "  .venv/ansible-validation/bin/python -m pip install "
                + " ".join(shlex.quote(package) for package in missing),
            )
        )
    lines.extend(("", f"Exact rerun: {rerun_command(argv)}", f"Overall status: {overall}"))
    lines.extend(("", "Live verification: NOT RUN — requires separate authorization"))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    root = Path.cwd()
    try:
        args = parse_args(raw_args, root)
        inventory = build_inventory(args, root)
        results = run_tools(inventory, root)
        overall, exit_code = aggregate_status(results, inventory.coverage_errors)
        print(render_report(inventory, results, raw_args, overall))
        return exit_code
    except InvocationError as error:
        print(f"Static validation\n=================\nInvocation error: {error}\nOverall status: FAIL")
        print("\nLive verification: NOT RUN — requires separate authorization")
        return 2
    except Exception as error:  # Keep unexpected runtime failures visible to CLI callers.
        print(f"Static validation\n=================\nRuntime error: {error}\nOverall status: FAIL")
        print("\nLive verification: NOT RUN — requires separate authorization")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
