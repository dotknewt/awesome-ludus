"""Small path-safety filters for the Docker collector role."""

import posixpath
import re
from datetime import datetime

from ansible.errors import AnsibleFilterError


_STATE_ROOTS = ("/var/lib/", "/srv/", "/mnt/", "/opt/")
_SANDBOX_HIDDEN = ("/dev", "/home", "/proc", "/root", "/run/user", "/sys", "/tmp", "/var/tmp")
_RFC3339 = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,9})?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


def normalize_path(value):
    """Return a normalized absolute path, rejecting dot components and aliases."""
    if not isinstance(value, str) or not value.startswith("/"):
        raise AnsibleFilterError("path must be an absolute string")
    if any(part in (".", "..") for part in value.split("/")):
        raise AnsibleFilterError("path must not contain dot segments")
    normalized = posixpath.normpath(value)
    if value != normalized:
        raise AnsibleFilterError("path must already be normalized without a trailing slash")
    return normalized


def path_ancestors(value):
    """Return lexical ancestors from root through the normalized path."""
    normalized = normalize_path(value)
    parts = [part for part in normalized.split("/") if part]
    return ["/"] + ["/" + "/".join(parts[:index]) for index in range(1, len(parts) + 1)]


def paths_overlap(left, right):
    """Return true when either normalized path contains the other."""
    left, right = normalize_path(left), normalize_path(right)
    return posixpath.commonpath((left, right)) in (left, right)


def dedicated_state_path(value):
    """Constrain writable state to a dedicated subtree outside system roots."""
    normalized = normalize_path(value)
    return any(normalized.startswith(root) and normalized != root[:-1] for root in _STATE_ROOTS)


def sandbox_accessible(value):
    """Reject paths hidden by ProtectHome or private temporary directories."""
    normalized = normalize_path(value)
    return not any(normalized == root or normalized.startswith(root + "/") for root in _SANDBOX_HIDDEN)


def docker_envelope_valid(value):
    """Validate one bounded Docker json-file envelope without retaining it."""
    if not isinstance(value, dict):
        return False
    if not isinstance(value.get("log"), str) or value.get("stream") not in ("stdout", "stderr"):
        return False
    timestamp = value.get("time")
    match = _RFC3339.fullmatch(timestamp) if isinstance(timestamp, str) else None
    if match is None:
        return False
    fraction = (match.group("fraction") or "")[:7]
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    try:
        parsed = datetime.fromisoformat(match.group("head") + fraction + zone)
    except ValueError:
        return False
    return parsed.tzinfo is not None


class FilterModule:
    def filters(self):
        return {
            "splunk_container_normalize_path": normalize_path,
            "splunk_container_path_ancestors": path_ancestors,
            "splunk_container_paths_overlap": paths_overlap,
            "splunk_container_dedicated_state_path": dedicated_state_path,
            "splunk_container_sandbox_accessible": sandbox_accessible,
            "splunk_container_docker_envelope_valid": docker_envelope_valid,
        }
