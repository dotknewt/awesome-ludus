"""Strict local active-config resolution and private role staging."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .models import ActiveConfig, Capabilities, Checkout, Manifest, ResolvedRole, StagedRole

_POLICY = 1
_ARCHIVE_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tgz", ".tbz2", ".txz", ".tar", ".zip", ".gz", ".bz2", ".xz", ".zst")
_IDENTITY = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_EXCLUDED_DIRS = {".git", "__pycache__"}


class SourceError(ValueError):
    """Invalid, ambiguous, or changing local role source."""


class MissingRolesError(SourceError):
    """Structured missing-role result; callers must sanitize before display."""

    def __init__(self, identities: tuple[str, ...], search_root: Path, label: str = "missing role identities"):
        self.identities = tuple(identities)
        self.search_root = Path(search_root)
        super().__init__(
            label + " " + ", ".join(self.identities)
            + f"; searched {self.search_root}"
        )


def safe_missing_roles_message(
    error: MissingRolesError,
    safe_identities: tuple[str, ...],
    known_secrets: tuple[str, ...],
) -> str:
    """Format only structured, pre-screened role identities and a safe local path."""
    if not isinstance(error, MissingRolesError):
        return "Configured roles could not be resolved safely"
    secrets = tuple(secret for secret in known_secrets if isinstance(secret, str) and secret)
    visible = tuple(
        identity for identity in safe_identities
        if isinstance(identity, str)
        and identity in error.identities
        and not any(secret in identity for secret in secrets)
    )
    path = str(error.search_root)
    if any(secret in path for secret in secrets) or any(ord(char) < 32 for char in path):
        path = "[path suppressed]"
    names = ", ".join(visible) if visible else "[role names suppressed]"
    return f"missing configured roles {names}; searched {path}"


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise SourceError("configuration mapping keys must be scalar") from exc
        if duplicate:
            raise SourceError(f"duplicate configuration key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _safe_identity(value: Any) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or not _IDENTITY.fullmatch(value):
        raise SourceError("configured role identity is unsafe or dynamic")
    lowered = value.lower()
    if any(lowered.endswith(suffix) for suffix in _ARCHIVE_SUFFIXES):
        raise SourceError("role identity would be changed by archive suffix stripping")
    return value


def _add_identity(values: list[str], identity: Any) -> None:
    identity = _safe_identity(identity)
    if identity not in values:
        values.append(identity)


def parse_config(raw: str, capabilities: Capabilities) -> ActiveConfig:
    """Decode supported Ludus YAML config forms and hash the exact raw text."""
    del capabilities  # Current supported config shapes are fixed by the pinned research.
    if not isinstance(raw, str):
        raise SourceError("active configuration must be YAML text")
    try:
        data = yaml.load(raw, Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, SourceError) as exc:
        raise SourceError(f"invalid active configuration: {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"defaults", "global_role_vars", "ludus", "router"}:
        raise SourceError("active configuration must use the supported Ludus config shape")
    if "ludus" not in data or not isinstance(data["ludus"], list):
        raise SourceError("active configuration requires a ludus VM list")
    roles: list[str] = []
    vm_roles: dict[str, set[str]] = {}
    dependencies: list[tuple[str, str]] = []
    defaults = data.get("defaults", {})
    global_role_vars = data.get("global_role_vars", {})
    router = data.get("router", {})
    if not isinstance(defaults, dict) or not isinstance(global_role_vars, dict) or not isinstance(router, dict):
        raise SourceError("defaults, global_role_vars, and router must be mappings")
    for vm in data["ludus"]:
        if not isinstance(vm, dict) or not isinstance(vm.get("vm_name"), str) or not vm["vm_name"].strip():
            raise SourceError("each ludus VM must be a mapping with nonempty vm_name")
        vm_name = vm["vm_name"]
        if vm_name in vm_roles:
            raise SourceError(f"duplicate or ambiguous VM identity: {vm_name}")
        assigned: set[str] = set()
        vm_roles[vm_name] = assigned
        if "roles" in vm:
            role_list = vm["roles"]
            if not isinstance(role_list, list):
                raise SourceError("role declarations must be a list")
            for entry in role_list:
                if isinstance(entry, str):
                    role_name = _safe_identity(entry)
                    assigned.add(role_name)
                    _add_identity(roles, role_name)
                elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                    role_name = _safe_identity(entry["name"])
                    if set(entry) - {"name", "depends_on"}:
                        raise SourceError("unsupported role declaration fields")
                    assigned.add(role_name)
                    _add_identity(roles, role_name)
                    role_dependencies = entry.get("depends_on", [])
                    if not isinstance(role_dependencies, list):
                        raise SourceError("depends_on must be a list")
                    for dependency in role_dependencies:
                        if not isinstance(dependency, dict) or set(dependency) != {"vm_name", "role"}:
                            raise SourceError("dependency must contain exactly vm_name and role")
                        target_vm = dependency["vm_name"]
                        if not isinstance(target_vm, str) or not target_vm.strip():
                            raise SourceError("dependency vm_name must be a nonempty string")
                        target_role = _safe_identity(dependency["role"])
                        dependencies.append((target_vm, target_role))
                        _add_identity(roles, target_role)
                else:
                    raise SourceError("role declaration must be a string or a named mapping")
    for target_vm, target_role in dependencies:
        assigned = vm_roles.get(target_vm)
        if assigned is None:
            raise SourceError(f"dependency references unknown or ambiguous VM: {target_vm}")
        if target_role not in assigned:
            raise SourceError(f"dependency VM {target_vm} does not assign role {target_role}")
    return ActiveConfig(hashlib.sha256(raw.encode("utf-8")).hexdigest(), tuple(roles))


def _checkout_root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise SourceError("checkout root must not be a symlink")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise SourceError("checkout path is not a directory")
    ansible = resolved / "ansible"
    roles = ansible / "roles"
    if ansible.is_symlink() or roles.is_symlink() or not roles.is_dir():
        raise SourceError("checkout has no ansible/roles directory")
    return resolved


def _git_environment() -> dict[str, str]:
    """Prevent inherited Git path/discovery overrides redirecting checkout lookup."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def discover_checkout(cwd: Path, override: Path | None) -> Checkout:
    """Find the actual Git worktree root from override/cwd, never module location."""
    start = Path(override if override is not None else cwd).expanduser()
    if start.is_symlink():
        raise SourceError("checkout location must not be a symlink")
    try:
        start = start.resolve(strict=True)
        if not start.is_dir():
            raise SourceError("checkout location is not a directory")
        git_root = subprocess.check_output(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            env=_git_environment(),
        ).strip()
    except SourceError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceError("working directory is not inside a Git checkout") from exc
    root = _checkout_root(Path(git_root))
    try:
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            env=_git_environment(),
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceError("could not identify checkout revision") from exc
    return Checkout(root=root, revision=revision or None)


def _contained(base: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise SourceError("role mapping must be a contained relative path")
    candidate = base.resolve(strict=True)
    for part in rel.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise SourceError("role paths must not contain symlinks")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(base.resolve(strict=True))
    except ValueError as exc:
        raise SourceError("role path escapes checkout role root") from exc
    if not resolved.is_dir():
        raise SourceError("resolved role path is not a directory")
    return resolved


def _contained_if_present(base: Path, relative: str) -> Path | None:
    rel = Path(relative)
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise SourceError("role mapping must be a contained relative path")
    candidate = base.resolve(strict=True)
    for part in rel.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise SourceError("role paths must not contain symlinks")
        if not candidate.exists():
            return None
    return _contained(base, relative)


def _path_without_symlink_ancestors(path: Path, label: str) -> Path:
    expanded = Path(path).expanduser()
    if ".." in expanded.parts:
        raise SourceError(f"{label} path must not contain parent traversal")
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    candidate = Path(expanded.anchor)
    for part in expanded.parts[1:]:
        if part in {"", "."}:
            continue
        candidate = candidate / part
        if candidate.is_symlink():
            raise SourceError(f"{label} path must not traverse symlinks")
    return candidate


def _metadata(role_dir: Path) -> tuple[str, str]:
    metadata = role_dir / "meta" / "main.yml"
    if not metadata.is_file():
        metadata = role_dir / "meta" / "main.yaml"
    if not metadata.is_file():
        raise SourceError(f"role metadata missing: {role_dir.name}")
    try:
        data = yaml.load(metadata.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, SourceError) as exc:
        raise SourceError(f"invalid role metadata: {role_dir.name}") from exc
    info = data.get("galaxy_info") if isinstance(data, dict) else None
    author = info.get("author") if isinstance(info, dict) else None
    role_name = info.get("role_name") if isinstance(info, dict) else None
    if not isinstance(author, str) or not author.strip() or not isinstance(role_name, str) or not role_name.strip():
        raise SourceError(f"role metadata author and role_name must be nonempty: {role_dir.name}")
    return author.strip(), role_name.strip()


def _load_mappings(root: Path) -> dict[str, str]:
    path = root / "ansible" / "role-identities.yml"
    if path.is_symlink():
        raise SourceError("identity mapping file must not be a symlink")
    if not path.exists():
        return {}
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, SourceError) as exc:
        raise SourceError("invalid ansible/role-identities.yml") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("roles"), dict):
        raise SourceError("identity mapping requires schema_version: 1 and roles mapping")
    result = {}
    paths = set()
    for identity, relative in data["roles"].items():
        key = _safe_identity(identity)
        if not isinstance(relative, str) or not relative:
            raise SourceError("identity mappings require relative directory strings")
        if relative in paths:
            raise SourceError("multiple identities map to the same role directory")
        paths.add(relative)
        result[key] = relative
    return result


def _static_role_references(role_dir: Path) -> tuple[str, ...]:
    """Read only static include/import and metadata dependency identities."""
    references: list[str] = []
    metadata_paths = (role_dir / "meta/main.yml", role_dir / "meta/main.yaml")
    metadata_path = next((path for path in metadata_paths if path.is_file()), None)
    if metadata_path is not None:
        metadata = yaml.load(metadata_path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
        if not isinstance(metadata, dict):
            raise SourceError(f"invalid metadata mapping in role {role_dir.name}")
        dependencies = metadata.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise SourceError(f"metadata dependencies must be a list in role {role_dir.name}")
        for dependency in dependencies:
            if isinstance(dependency, str):
                identity = dependency
            elif isinstance(dependency, dict) and isinstance(dependency.get("role"), str):
                identity = dependency["role"]
            else:
                raise SourceError(f"metadata dependency must have a static role identity in {role_dir.name}")
            references.append(_safe_identity(identity))

    tasks_root = role_dir / "tasks"
    if tasks_root.exists():
        _, entries = _walk(role_dir)
        for relative, kind, _, _ in entries:
            rel = Path(relative)
            if kind != "file" or not rel.parts or rel.parts[0] != "tasks" or rel.suffix.lower() not in {".yml", ".yaml"}:
                continue
            task_path = role_dir / rel
            try:
                task_data = yaml.load(task_path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
            except (OSError, UnicodeError, yaml.YAMLError, SourceError) as exc:
                raise SourceError(f"invalid task YAML in role {role_dir.name}: {rel.as_posix()}") from exc

            def module_is_role(value: str) -> bool:
                module = value.rsplit(".", 1)[-1]
                return module in {"include_role", "import_role"}

            def add_action(module: str, inline_args: list[str], task: dict[str, Any], rel: Path) -> None:
                if not module_is_role(module):
                    return
                values: dict[str, Any] = {}
                task_args = task.get("args", {})
                if isinstance(task_args, dict):
                    values.update(task_args)
                for item in inline_args:
                    if "=" in item:
                        key, value = item.split("=", 1)
                        values.setdefault(key, value)
                if "name" not in values or not isinstance(values["name"], str):
                    raise SourceError(f"role include/import must use a static name in {rel.as_posix()}")
                references.append(_safe_identity(values["name"]))

            def inspect_task(task: Any, rel: Path) -> None:
                if not isinstance(task, dict):
                    raise SourceError(f"task entries must be mappings in {rel.as_posix()}")
                for key, value in task.items():
                    if isinstance(key, str) and (key in {"include_role", "import_role"} or key.endswith((".include_role", ".import_role"))):
                        if isinstance(value, str):
                            identity = value
                        elif isinstance(value, dict) and isinstance(value.get("name"), str):
                            identity = value["name"]
                        else:
                            raise SourceError(f"role include/import must use a static name in {rel.as_posix()}")
                        references.append(_safe_identity(identity))
                for action_key in ("action", "local_action"):
                    action = task.get(action_key)
                    if isinstance(action, str):
                        try:
                            tokens = shlex.split(action)
                        except ValueError as exc:
                            raise SourceError(f"invalid action syntax in {rel.as_posix()}") from exc
                        if tokens:
                            add_action(tokens[0], tokens[1:], task, rel)
                    elif isinstance(action, dict):
                        module = action.get("module", action.get("__ansible_module__"))
                        if isinstance(module, str) and module_is_role(module):
                            synthetic = dict(task)
                            task_args = task.get("args", {})
                            action_args = action.get("args", {})
                            if not isinstance(action_args, dict):
                                raise SourceError(f"action args must be a mapping in {rel.as_posix()}")
                            if not isinstance(task_args, dict):
                                task_args = {}
                            name_values = [
                                candidate
                                for candidate in (
                                    task_args.get("name"),
                                    action_args.get("name"),
                                    action.get("name"),
                                )
                                if candidate is not None
                            ]
                            if any(not isinstance(candidate, str) for candidate in name_values):
                                raise SourceError(f"role include/import must use a static name in {rel.as_posix()}")
                            if len(set(name_values)) > 1:
                                raise SourceError(f"conflicting role names in action mapping in {rel.as_posix()}")
                            merged_args = {**task_args, **action_args}
                            if name_values:
                                merged_args["name"] = name_values[0]
                            synthetic["args"] = merged_args
                            add_action(module, [], synthetic, rel)
                        elif isinstance(module, str):
                            continue
                        elif action:
                            raise SourceError(f"unsupported action mapping in {rel.as_posix()}")
                for section in ("block", "rescue", "always"):
                    children = task.get(section, [])
                    if not isinstance(children, list):
                        raise SourceError(f"{section} must be a task list in {rel.as_posix()}")
                    for child in children:
                        inspect_task(child, rel)

            if task_data is None:
                continue
            if not isinstance(task_data, list):
                raise SourceError(f"task file must contain a task list: {rel.as_posix()}")
            for task in task_data:
                inspect_task(task, rel)
    return tuple(dict.fromkeys(references))


def resolve_roles(checkout: Checkout, config: ActiveConfig, capabilities: Capabilities) -> tuple[ResolvedRole, ...]:
    """Resolve identities exact-folder-first, with only explicit mapping fallback."""
    del capabilities
    root = _checkout_root(checkout.root)
    roles_root = (root / "ansible" / "roles").resolve(strict=True)
    mappings = _load_mappings(root)
    def select(name: str) -> tuple[Path | None, bool]:
        exact_path = roles_root / name
        exact = _contained(roles_root, name) if exact_path.exists() or exact_path.is_symlink() else None
        mapped_relative = mappings.get(name)
        mapped = _contained_if_present(roles_root, mapped_relative) if mapped_relative is not None else None
        if exact is not None and mapped_relative is not None and mapped != exact:
            raise SourceError(f"identity mapping conflicts with exact role folder: {name}")
        return exact or mapped, exact is not None

    configured = tuple(dict.fromkeys(_safe_identity(name) for name in config.roles))
    selected: dict[str, tuple[Path, bool]] = {}
    missing: set[str] = set()
    source_owners: dict[Path, str] = {}
    for name in configured:
        folder, is_exact = select(name)
        if folder is None:
            missing.add(name)
            continue
        owner = source_owners.get(folder)
        if owner is not None and owner != name:
            raise SourceError(f"multiple configured identities resolve to one role directory: {owner}, {name}")
        source_owners[folder] = name
        selected[name] = (folder, is_exact)

    if missing:
        raise MissingRolesError(tuple(sorted(missing)), roles_root, "missing configured roles")

    resolved: list[ResolvedRole] = []
    for name in configured:
        folder, is_exact = selected[name]
        manifest(folder)  # rejects symlinks and special files within this used role only
        author, metadata_name = _metadata(folder)
        evidence = ["exact-folder" if is_exact else "explicit-mapping", f"metadata-author:{author}"]
        if metadata_name != name:
            evidence.append(f"metadata-role-name-disagrees:{metadata_name}")
        resolved.append(ResolvedRole(identity=name, source=folder, resolution_evidence=tuple(evidence)))

    # Validate references from only the selected role sources. Do not traverse
    # unrelated role metadata or infer identities from variables/templates.
    pending = list(configured)
    checked: set[str] = set()
    while pending:
        name = pending.pop()
        if name in checked:
            continue
        checked.add(name)
        folder, _ = selected.get(name, (None, False))
        if folder is None:
            folder, _ = select(name)
            if folder is None:
                missing.add(name)
                continue
            manifest(folder)
            _metadata(folder)
            selected[name] = (folder, False)
        pending.extend(ref for ref in _static_role_references(folder) if ref not in checked)
    if missing:
        raise MissingRolesError(tuple(sorted(missing)), roles_root)
    return tuple(resolved)


def _excluded(relative: Path) -> bool:
    return any(part in _EXCLUDED_DIRS for part in relative.parts) or relative.name.endswith(".pyc")


def _walk(directory: Path):
    if directory.is_symlink():
        raise SourceError("manifest root must not be a symlink")
    root = directory.resolve(strict=True)
    if not root.is_dir():
        raise SourceError("manifest target is not a directory")
    entries = []

    def walk_error(error: OSError) -> None:
        raise SourceError(f"could not enumerate role source: {error}") from error

    for current, dirs, files in os.walk(root, topdown=True, onerror=walk_error, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if not _excluded((current_path / d).relative_to(root)))
        files.sort()
        for name in list(dirs) + files:
            path = current_path / name
            relative = path.relative_to(root)
            if _excluded(relative):
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise SourceError(f"symlink not allowed in role source: {relative.as_posix()}")
            if stat.S_ISDIR(mode):
                entries.append((relative.as_posix(), "directory", 0, ""))
            elif stat.S_ISREG(mode):
                exec_bits = stat.S_IMODE(mode) & 0o111
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                entries.append((relative.as_posix(), "file", exec_bits, digest))
            else:
                raise SourceError(f"special file not allowed in role source: {relative.as_posix()}")
    return root, tuple(sorted(entries))


def _manifest_from_entries(entries: tuple[tuple[str, str, int, str], ...]) -> Manifest:
    payload = json.dumps([_POLICY, entries], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return Manifest(policy=_POLICY, digest=hashlib.sha256(payload).hexdigest(), entries=entries)


def manifest(directory: Path) -> Manifest:
    """Hash sorted meaningful files, preserving file types and executable bits."""
    _, entries = _walk(Path(directory))
    return _manifest_from_entries(entries)


def _copy_tree(source_root: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    destination.chmod(0o700)
    _, entries = _walk(source_root)
    for relative, kind, executable, _ in entries:
        source = source_root / relative
        target = destination / relative
        if kind == "directory":
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.chmod(0o700)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            target.chmod(0o600 | executable)


def stage_roles(roles: tuple[ResolvedRole, ...], stage_root: Path) -> tuple[StagedRole, ...]:
    """Copy private per-role snapshots and reject any source/stage drift."""
    stage_root = _path_without_symlink_ancestors(Path(stage_root), "staging root")
    stage_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage_root = _path_without_symlink_ancestors(stage_root, "staging root")
    stage_root.chmod(0o700)
    stage_root = stage_root.resolve(strict=True)
    staged = []
    for role in roles:
        identity = _safe_identity(role.identity)
        source_root = _path_without_symlink_ancestors(Path(role.source), "role source")
        source_root = source_root.resolve(strict=True)
        before = manifest(source_root)
        destination = stage_root / identity
        if destination.exists() or destination.is_symlink():
            raise SourceError(f"staging destination already exists: {role.identity}")
        try:
            _copy_tree(source_root, destination)
            after = manifest(source_root)
            copied = manifest(destination)
            if before != after or before != copied:
                raise SourceError(f"role source changed during staging: {identity}")
        except BaseException:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        staged.append(StagedRole(role=role, directory=destination, manifest=copied))
    return tuple(staged)
