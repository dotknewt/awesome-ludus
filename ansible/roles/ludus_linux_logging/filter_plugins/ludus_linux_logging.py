"""Small pure transforms for the pinned upstream auditd/Laurel text inputs."""

from __future__ import annotations

import json
import re
import shlex


def _audit_tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError as exc:
        raise ValueError(f"cannot parse upstream audit rule {line!r}: {exc}") from exc


def extract_audit_paths(text: str) -> list[str]:
    """Return unique targets from watch, path=, and dir= predicates."""
    targets: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = _audit_tokens(stripped)
        candidates: list[str] = []
        for index, token in enumerate(tokens):
            if token == "-w" and index + 1 < len(tokens):
                candidates.append(tokens[index + 1])
            elif token == "-F" and index + 1 < len(tokens):
                predicate = tokens[index + 1]
                if predicate.startswith(("path=", "dir=")):
                    candidates.append(predicate.split("=", 1)[1])
        for target in candidates:
            if target.startswith("/") and target not in targets:
                targets.append(target)
    return targets


_IDENTITY_FIELDS = {
    "uid": "passwd", "euid": "passwd", "suid": "passwd", "fsuid": "passwd", "auid": "passwd",
    "gid": "group", "egid": "group", "sgid": "group", "fsgid": "group",
    "obj_uid": "passwd", "obj_gid": "group",
}
_SELINUX_FIELDS = {
    "subj_user", "subj_role", "subj_type", "subj_sen", "subj_clr",
    "obj_user", "obj_role", "obj_type", "obj_sen", "obj_clr",
}
_FIELD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)((?:!=|<=|>=|=|<|>))(.+)$")


def _numeric_identity(value: str) -> bool:
    if value.lstrip("-").isdecimal():
        return True
    try:
        int(value, 0)
        return True
    except ValueError:
        return False


def _predicates(tokens: list[str]):
    index = 0
    while index < len(tokens):
        if tokens[index] == "-F" and index + 1 < len(tokens):
            yield tokens[index + 1]
            index += 2
        else:
            index += 1


def extract_audit_identities(text: str) -> list[dict[str, str]]:
    """Find named uid/gid operands requiring existing passwd/group records."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for predicate in _predicates(_audit_tokens(stripped)):
            match = _FIELD.fullmatch(predicate)
            if match is None:
                continue
            field, _operator, operand = match.groups()
            database = _IDENTITY_FIELDS.get(field)
            if database is None:
                continue
            if _numeric_identity(operand):
                continue
            if operand.lower() == "unset":
                continue
            key = (database, operand)
            if key not in seen:
                seen.add(key)
                found.append({"database": database, "name": operand})
    return found


def extract_selinux_predicates(text: str) -> list[str]:
    predicates: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for predicate in _predicates(_audit_tokens(stripped)):
            match = _FIELD.fullmatch(predicate)
            if match is not None and match.group(1) in _SELINUX_FIELDS and predicate not in predicates:
                predicates.append(predicate)
    return predicates


def _identity_status(identity_stats: list[dict]) -> dict[tuple[str, str], int]:
    return {
        (str(item.get("item", {}).get("database", "")), str(item.get("item", {}).get("name", ""))): int(item.get("rc", 2))
        for item in identity_stats
    }


def _effective_unit_directives(unit_text: str) -> dict[str, list[str]]:
    """Collect effective directives from systemctl-cat output, including resets."""
    section = ""
    directives: dict[str, list[str]] = {}
    for line in unit_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section not in {"Unit", "Service"} or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key not in {"Requires", "After", "Type", "ExecStart", "ExecStartPost", "RemainAfterExit"}:
            continue
        value = value.strip()
        if not value and key in {"Requires", "After", "ExecStart", "ExecStartPost"}:
            directives[key] = []
        elif value:
            if key in {"Type", "RemainAfterExit"}:
                directives[key] = [value]
            else:
                directives.setdefault(key, []).append(value)
    return directives


def _parse_loader_command(value: str) -> list[str] | None:
    if value.startswith(("+", "!", "|", "@", ":")):
        return None
    if value.startswith("-"):
        value = value[1:].lstrip()
    try:
        argv = shlex.split(value, posix=True)
    except ValueError:
        return None
    if argv not in (["/sbin/augenrules", "--load"], ["/usr/sbin/augenrules", "--load"]):
        return None
    return argv


def auditd_loader_contract(auditd_unit_text: str, rules_unit_text: str) -> dict | None:
    """Recognize supported effective unit layouts, refusing ambiguous overrides."""
    auditd = _effective_unit_directives(auditd_unit_text)
    rules = _effective_unit_directives(rules_unit_text)
    requirements = " ".join(auditd.get("Requires", [])).split()
    ordering = " ".join(auditd.get("After", [])).split()
    if "audit-rules.service" in requirements or "audit-rules.service" in ordering:
        if "audit-rules.service" not in requirements or "audit-rules.service" not in ordering:
            return None
        if auditd.get("ExecStartPost", []):
            return None
        starts = rules.get("ExecStart", [])
        remain = rules.get("RemainAfterExit", [])
        if (rules.get("Type") != ["oneshot"] or len(starts) != 1
                or (remain and remain[-1].lower() not in {"no", "false", "0"})):
            return None
        argv = _parse_loader_command(starts[0])
        if argv is None:
            return None
        return {"unit": "audit-rules.service", "directive": "ExecStart", "argv": argv}

    post = auditd.get("ExecStartPost", [])
    if len(post) != 1:
        return None
    argv = _parse_loader_command(post[0])
    if argv is None:
        return None
    return {"unit": "auditd.service", "directive": "ExecStartPost", "argv": argv}


def validate_auditd_startpost(unit_text: str) -> bool:
    """Compatibility predicate for the supported legacy auditd unit shape."""
    directives = _effective_unit_directives(unit_text)
    post = directives.get("ExecStartPost", [])
    return len(post) == 1 and _parse_loader_command(post[0]) is not None


def auditd_rules_loader_succeeded(output: str) -> bool:
    """Check systemd's recorded successful oneshot execution, not active state."""
    fields = dict(re.findall(r"(?m)^([A-Za-z]+)=(.*)$", output))
    return (
        fields.get("Result") == "success"
        and fields.get("ExecMainCode") == "1"  # CLD_EXITED
        and fields.get("ExecMainStatus") == "0"
    )


def auditd_startpost_succeeded(output: str) -> bool:
    """Require exactly one named systemd ExecStartPost result to be successful."""
    hook_lines = [line for line in output.splitlines() if line.startswith("ExecStartPost=")]
    if len(hook_lines) != 1:
        return False
    if hook_lines[0].count("{") != 1 or hook_lines[0].count("}") != 1:
        return False
    match = re.fullmatch(
        r"ExecStartPost=\{\s*path=([^ ;]+)\s*;\s*argv\[\]=([^;]+?)\s*;"
        r".*?\bcode=([^ ;]+)\s*;\s*status=([^ }]+)\s*\}",
        hook_lines[0],
    )
    if match is None:
        return False
    path, argv, code, status = match.groups()
    return (
        path in {"/sbin/augenrules", "/usr/sbin/augenrules"}
        and shlex.split(argv.strip()) == [path, "--load"]
        and code == "exited"
        and status == "0"
    )


def transform_audit_rules(
    text: str,
    path_stats: list[dict],
    identity_stats: list[dict],
    selinux_present: bool,
) -> str:
    """Remove unsafe global controls and record only resolvable omissions."""
    exists = {
        str(item.get("item", "")): bool(item.get("stat", {}).get("exists", False))
        for item in path_stats
    }
    identities = _identity_status(identity_stats)
    output: list[str] = ["# Managed by ludus_linux_logging; source attribution: ConstructingDefense."]
    seen_active: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue
        tokens = _audit_tokens(stripped)
        if tokens and tokens[0] in {"-D", "-e", "-i"}:
            output.append(f"# ludus_linux_logging omitted global control {tokens[0]}: {stripped}")
            continue
        reasons: list[str] = []
        for path in extract_audit_paths(stripped):
            if exists.get(path) is False:
                reasons.append(f"absent path {path}")
        for predicate in _predicates(tokens):
            match = _FIELD.fullmatch(predicate)
            if match is None:
                continue
            field, _operator, operand = match.groups()
            database = _IDENTITY_FIELDS.get(field)
            if database is not None:
                if not _numeric_identity(operand) and operand.lower() != "unset":
                    rc = identities.get((database, operand))
                    if rc is None:
                        raise ValueError(f"no preflight identity result for named {database} operand {operand!r}")
                    if rc == 2:
                        reasons.append(f"unresolvable named {database} operand {operand}")
                    elif rc != 0:
                        raise ValueError(f"unexpected getent status {rc} for named {database} operand {operand!r}")
            if field in _SELINUX_FIELDS and not selinux_present:
                reasons.append(f"SELinux absent for predicate {predicate}")
        if reasons:
            output.append(f"# ludus_linux_logging omitted ({'; '.join(reasons)}): {stripped}")
        elif stripped in seen_active:
            output.append(f"# ludus_linux_logging omitted exact duplicate rule: {stripped}")
        else:
            output.append(line)
            seen_active.add(stripped)
    return "\n".join(output) + "\n"


def transform_laurel_config(text: str, log_dir: str, log_file: str, user: str, readers: list[str]) -> str:
    """Preserve upstream Laurel policy while overriding only identity and paths."""
    substitutions = (
        (r"(?m)^directory\s*=\s*.*$", f"directory = {json.dumps(log_dir)}"),
        (r"(?m)^user\s*=\s*.*$", f"user = {json.dumps(user)}"),
        (r'(?m)^file\s*=\s*"[A-Za-z0-9_.-]+"\s*$', f"file = {json.dumps(log_file)}"),
        (r"(?m)^read-users\s*=\s*.*$", f"read-users = {json.dumps(readers)}"),
    )
    result = text
    for pattern, replacement in substitutions:
        result, count = re.subn(pattern, replacement, result, count=1)
        if count != 1:
            raise ValueError(f"expected exactly one Laurel config setting matching {pattern!r}, found {count}")
    return "# Managed by ludus_linux_logging; Laurel GPL-3.0-or-later.\n" + result


class FilterModule:
    def filters(self):
        return {
            "ludus_linux_logging_extract_audit_paths": extract_audit_paths,
            "ludus_linux_logging_extract_audit_identities": extract_audit_identities,
            "ludus_linux_logging_extract_selinux_predicates": extract_selinux_predicates,
            "ludus_linux_logging_transform_audit_rules": transform_audit_rules,
            "ludus_linux_logging_transform_laurel_config": transform_laurel_config,
            "ludus_linux_logging_validate_auditd_startpost": validate_auditd_startpost,
            "ludus_linux_logging_auditd_startpost_succeeded": auditd_startpost_succeeded,
            "ludus_linux_logging_auditd_loader_contract": auditd_loader_contract,
            "ludus_linux_logging_auditd_rules_loader_succeeded": auditd_rules_loader_succeeded,
        }
