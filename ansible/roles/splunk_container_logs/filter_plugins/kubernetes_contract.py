"""Pure-data validation helpers for the bounded Kubernetes collector contract."""

import base64
import hashlib
import posixpath
import re
import ssl


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_LABEL_NAME = re.compile(r"^[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")
_PERSISTENT_PATH = re.compile(r"^/var/addon/splunk/[A-Za-z0-9._-]+$")


def _label_key_valid(key):
    if not isinstance(key, str) or not key or key.count("/") > 1:
        return False
    if "/" in key:
        prefix, name = key.split("/", 1)
        if len(prefix) > 253 or not prefix:
            return False
        if any(not _DNS_LABEL.fullmatch(part) for part in prefix.split(".")):
            return False
    else:
        name = key
    return len(name) <= 63 and bool(_LABEL_NAME.fullmatch(name))


def kubernetes_label_pair_valid(key, value):
    """Return whether a nonempty selector pair follows Kubernetes label syntax."""
    return (
        _label_key_valid(key)
        and isinstance(value, str)
        and 0 < len(value) <= 63
        and bool(_LABEL_NAME.fullmatch(value))
    )


def kubernetes_credential_contract(token_b64, ca_b64=""):
    """Strictly decode credentials and return only a CA flag and framed digest."""
    token = base64.b64decode(token_b64, validate=True)
    if not token.strip():
        raise ValueError("splunk_platform_hec_token decodes empty")
    ca = base64.b64decode(ca_b64, validate=True) if ca_b64 else b""
    if ca:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ca.decode("utf-8"))
    digest = hashlib.sha256()
    for value in (token, ca):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return {"has_ca": bool(ca), "digest": digest.hexdigest()}


def kubernetes_persistent_paths_valid(paths):
    """Require two normalized, dedicated, nonoverlapping persistent paths."""
    if not isinstance(paths, (list, tuple)) or len(paths) != 2:
        return False
    normalized = []
    for path in paths:
        if not isinstance(path, str) or not _PERSISTENT_PATH.fullmatch(path):
            return False
        if path != posixpath.normpath(path) or any(part in (".", "..") for part in path.split("/")):
            return False
        normalized.append(path)
    left, right = normalized
    return not (left == right or left.startswith(right + "/") or right.startswith(left + "/"))


def _normalized_absolute_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError("hostPath must be an absolute string without NUL")
    return "/" + posixpath.normpath(value).lstrip("/")


def kubernetes_host_paths_disjoint(observed_paths, selected_paths):
    """Fail closed unless normalized observed and selected paths are disjoint."""
    if (
        not isinstance(observed_paths, (list, tuple))
        or not isinstance(selected_paths, (list, tuple))
        or not selected_paths
    ):
        return False
    try:
        observed = [_normalized_absolute_path(path) for path in observed_paths]
        selected = [_normalized_absolute_path(path) for path in selected_paths]
    except (TypeError, ValueError):
        return False
    return not any(
        posixpath.commonpath((left, right)) in (left, right)
        for left in observed
        for right in selected
    )


class FilterModule:
    def filters(self):
        return {
            "splunk_k8s_label_pair_valid": kubernetes_label_pair_valid,
            "splunk_k8s_credential_contract": kubernetes_credential_contract,
            "splunk_k8s_persistent_paths_valid": kubernetes_persistent_paths_valid,
            "splunk_k8s_host_paths_disjoint": kubernetes_host_paths_disjoint,
        }
