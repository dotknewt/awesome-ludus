"""Pinned, capability-separated Ludus CLI adapter (no import-time discovery)."""

from __future__ import annotations

import json
import os
import re
import signal
import selectors
import shutil
import subprocess
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import yaml

from . import models

_SUPPORTED = "2.3.10+fccf931e"
_MAX_OUTPUT = 1_048_576
_TIMEOUT = 30
_SAFE_USER = re.compile(r"^[A-Za-z0-9_-]+$")
_RANGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+\+[0-9A-Fa-f]+"
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_HISTORY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ROLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$")
_RANGE_STATES = {"DEPLOYING", "DESTROYING", "ERROR", "ABORTED", "DESTROYED", "NEVER DEPLOYED", "SUCCESS"}


class LudusAdapterError(models.DeploymentError):
    """Fixed, safe adapter diagnostic; never contains process/config payloads."""


@dataclass(frozen=True, repr=False)
class _CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


@dataclass(repr=False)
class _SecretRegistry:
    _values: set[str] = field(default_factory=set, repr=False)

    def add(self, value: str) -> None:
        if isinstance(value, str) and value:
            self._values.add(value)

    def values(self) -> tuple[str, ...]:
        return tuple(self._values)


@dataclass(frozen=True, repr=False)
class ResolvedContext:
    endpoint: str
    effective_user: str
    _api_key: str = field(repr=False)
    _proxy: str = field(repr=False)
    verify: bool
    executable: str
    _env: Any = field(repr=False)
    _secrets: _SecretRegistry = field(repr=False)

    def __reduce__(self):
        raise TypeError("resolved Ludus context cannot be serialized")


def _client_version_argv() -> tuple[str, ...]:
    return ("ludus", "version")


def _server_version_argv() -> tuple[str, ...]:
    return ("ludus", "version", "--verbose")


def _active_config_argv() -> tuple[str, ...]:
    return ("ludus", "range", "config", "get", "--range", "<range>", "--json")


def _status_argv() -> tuple[str, ...]:
    return ("ludus", "range", "status", "--range", "<range>", "--json")


def _installed_roles_argv() -> tuple[str, ...]:
    return ("ludus", "ansible", "role", "list", "--range", "<range>", "--json")


def _history_list_argv() -> tuple[str, ...]:
    return ("ludus", "range", "logs", "--history", "--range", "<range>", "--json")


def _upload_argv() -> tuple[str, ...]:
    return ("ludus", "ansible", "role", "add", "--directory", "<stage>", "--force", "--json")


def _launch_roles_argv() -> tuple[str, ...]:
    return ("ludus", "range", "deploy", "--range", "<range>", "--tags", "user-defined-roles", "--json")


def _launch_full_argv() -> tuple[str, ...]:
    return ("ludus", "range", "deploy", "--range", "<range>", "--json")


def _endpoint(value: Any) -> str:
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise LudusAdapterError("Ludus endpoint configuration is invalid", 2, "blocked")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LudusAdapterError("Ludus endpoint configuration is invalid", 2, "blocked")
    return value.rstrip("/")


def _resolve_settings(environ: dict[str, str], config: dict[str, Any]) -> tuple[str, str, bool]:
    config = _normalize_config_keys(config)
    configured_user = config.get("user", "")
    if configured_user or environ.get("LUDUS_USER", ""):
        raise LudusAdapterError("Ludus user impersonation is unsupported", 2, "blocked")
    env_url = environ.get("LUDUS_URL", "")
    config_url = config.get("url", "https://198.51.100.1:8080")
    endpoint = _endpoint(env_url if env_url else config_url)
    env_proxy = environ.get("LUDUS_PROXY", "")
    config_proxy = config.get("proxy", "")
    proxy = env_proxy if env_proxy else config_proxy
    if not isinstance(proxy, str) or any(ord(char) < 32 for char in proxy):
        raise LudusAdapterError("Ludus proxy configuration is invalid", 2, "blocked")
    env_verify = environ.get("LUDUS_VERIFY", "")
    verify: Any = env_verify if env_verify else config.get("verify", False)
    if isinstance(verify, str):
        if verify.lower() not in {"true", "false"}:
            raise LudusAdapterError("Ludus TLS verification setting is invalid", 2, "blocked")
        verify = verify.lower() == "true"
    if not isinstance(verify, bool):
        raise LudusAdapterError("Ludus TLS verification setting is invalid", 2, "blocked")
    return endpoint, proxy, verify


def _parse_versions(client_output: str, verbose_output: str) -> tuple[str, str]:
    """Parse only the separate source-labeled client and verbose server lines."""
    clean_client = _ANSI.sub("", client_output)
    clean_server = _ANSI.sub("", verbose_output)
    client_matches = re.findall(
        rf"(?im)^[^\r\n]*?\bLudus[ \t]+client[ \t]+({_VERSION})[ \t]*$",
        clean_client,
    )
    server_matches = re.findall(rf"(?im)\bLudus\s+Server\s+({_VERSION})\s+-", clean_server)
    if len(set(client_matches)) != 1 or len(set(server_matches)) != 1:
        raise LudusAdapterError("Ludus client/server version labels are missing or conflicting", 2, "blocked")
    client_version, server_version = client_matches[0], server_matches[0]
    if client_version != _SUPPORTED or server_version != _SUPPORTED:
        raise LudusAdapterError("Ludus client/server version is unsupported", 2, "blocked")
    return client_version, server_version


def _validate_range_id(value: str) -> str:
    if not isinstance(value, str) or not _RANGE_ID.fullmatch(value):
        raise LudusAdapterError("Range identifier is invalid", 2, "blocked")
    return value


def _validate_range_state(value: str) -> str:
    if not isinstance(value, str) or value not in _RANGE_STATES:
        raise LudusAdapterError("Ludus range state is unsupported", 2, "unknown")
    return value


def _safe_metadata_text(value: Any, secrets: tuple[str, ...]) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        return None
    if any(secret and secret in value for secret in secrets):
        return None
    return value


def _safe_history_id(value: Any, secrets: tuple[str, ...]) -> str | None:
    safe = _safe_metadata_text(value, secrets)
    if safe is None or not _HISTORY_ID.fullmatch(safe):
        return None
    return safe


def _classify_upload_response(
    value: Any, *, returncode: int = 0, timed_out: bool = False, truncated: bool = False,
) -> models.UploadResult:
    if timed_out or truncated or returncode != 0:
        return models.UploadResult("unknown", "Role upload outcome is unknown")
    if isinstance(value, dict) and value == {"result": "Successfully installed role"}:
        return models.UploadResult("confirmed", "Role upload confirmed")
    denials = {
        "You are not authorized to perform this ansible action",
        "Only administrators can perform global ansible actions",
    }
    if isinstance(value, dict) and set(value) == {"error"}:
        error = value["error"]
        if isinstance(error, str) and error in denials:
            return models.UploadResult("failure", "Role upload was denied")
    return models.UploadResult("unknown", "Role upload outcome is unknown")


_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|secret|credential|(?:api|private|access)[ _-]?key|^key$|(?:^|[_-])auth(?:entication|orization)?(?:[_-]|$))",
    re.I,
)


def _collect_sensitive_values(value: Any) -> frozenset[str]:
    collected: set[str] = set()
    active: set[int] = set()

    def visit(node: Any, inherited_sensitive: bool = False) -> None:
        if isinstance(node, str):
            if inherited_sensitive and node:
                collected.add(node)
            return
        if not isinstance(node, (dict, list, tuple)):
            return
        identity = id(node)
        if identity in active:
            raise LudusAdapterError("Configuration contains a recursive alias", 2, "blocked")
        active.add(identity)
        try:
            if isinstance(node, dict):
                for key, nested in node.items():
                    sensitive = inherited_sensitive or (isinstance(key, str) and bool(_SENSITIVE_KEY.search(key)))
                    visit(nested, sensitive)
            else:
                for nested in node:
                    visit(nested, inherited_sensitive)
        finally:
            active.remove(identity)

    try:
        visit(value)
    except LudusAdapterError:
        raise
    except Exception:
        raise LudusAdapterError("Configuration secrets cannot be inspected safely", 2, "blocked") from None
    return frozenset(collected)


def _register_config_secrets(context: ResolvedContext, config: Any) -> None:
    for secret in _collect_sensitive_values(config):
        context._secrets.add(secret)


def _register_role_secrets(context: ResolvedContext, role: models.StagedRole) -> None:
    for filename in ("main.yml", "main.yaml"):
        defaults = role.directory / "defaults" / filename
        if defaults.is_file():
            try:
                with defaults.open("r", encoding="utf-8") as stream:
                    parsed = yaml.safe_load(stream)
            except Exception:
                # Uncertain defaults make response sanitization unsafe; fail before mutation.
                raise LudusAdapterError("Staged role defaults cannot be safely inspected", 2, "blocked") from None
            for secret in _collect_sensitive_values(parsed):
                context._secrets.add(secret)


def _normalize_config_keys(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise LudusAdapterError("Ludus configuration shape is unsupported", 2, "blocked")
    normalized = {key.lower(): item for key, item in value.items()}
    if len(normalized) != len(value):
        raise LudusAdapterError("Ludus configuration keys are ambiguous", 2, "blocked")
    return normalized


def _load_config() -> dict[str, Any]:
    try:
        from .source import _UniqueKeyLoader

        directory = Path.home() / ".config" / "ludus"
        candidates = [path for path in directory.iterdir()
                      if path.name.lower() == "config" or path.name.lower().startswith("config.")] if directory.exists() else []
        if not candidates:
            return {}
        if len(candidates) != 1 or candidates[0].name not in {"config.yml", "config.yaml"}:
            raise LudusAdapterError("Ludus configuration files are unsupported or ambiguous", 2, "blocked")
        config_path = candidates[0]
        with config_path.open("r", encoding="utf-8") as stream:
            value = yaml.load(stream, Loader=_UniqueKeyLoader)
        return _normalize_config_keys(value)
    except LudusAdapterError:
        raise
    except Exception:
        raise LudusAdapterError("Ludus configuration is unreadable or malformed", 2, "blocked") from None


def resolve_context() -> ResolvedContext:
    """Resolve once without network access; only the environment supplies credentials."""
    key = os.environ.get("LUDUS_API_KEY", "")
    if not key:
        raise LudusAdapterError(
            "Set LUDUS_API_KEY securely in this process environment; keyring-only credentials are not supported by this utility yet.",
            2,
            "blocked",
        )
    parts = key.split(".")
    if len(parts) != 2 or not all(parts) or not _SAFE_USER.fullmatch(parts[0]) or parts[0].upper() == "ROOT":
        raise LudusAdapterError("LUDUS_API_KEY has an unsupported format or identity", 2, "blocked")
    executable = shutil.which("ludus")
    if not executable:
        raise LudusAdapterError("Ludus CLI executable is unavailable", 2, "blocked")
    config = _load_config()
    endpoint, proxy, verify_value = _resolve_settings(dict(os.environ), config)
    env_names = {
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    }
    child = {name: os.environ[name] for name in env_names if name in os.environ and not name.startswith("LUDUS_")}
    child["LUDUS_API_KEY"] = key
    child["LUDUS_PROXY"] = proxy
    secrets = _SecretRegistry()
    secrets.add(key)
    secrets.add(parts[1])
    secrets.add(proxy)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        proxy_value = child.get(name)
        if proxy_value:
            secrets.add(proxy_value)
            try:
                parsed_proxy = urlsplit(proxy_value)
                if parsed_proxy.username:
                    secrets.add(parsed_proxy.username)
                if parsed_proxy.password:
                    secrets.add(parsed_proxy.password)
            except ValueError:
                pass
    for secret in _collect_sensitive_values(config):
        secrets.add(secret)
    return ResolvedContext(endpoint, parts[0], key, proxy, verify_value, os.path.realpath(executable), MappingProxyType(child), secrets)


def _freeze_argv(context: ResolvedContext, argv: tuple[str, ...]) -> tuple[str, ...]:
    return (context.executable, *argv[1:], "--config", "/dev/null", "--url", context.endpoint,
            "--verify=" + ("true" if context.verify else "false"), "--user", "")


def _capture_process(
    argv: tuple[str, ...], timeout: float, max_output: int, env: dict[str, str] | None = None,
) -> _CommandResult:
    """Capture a local child with bounded memory, deadline and process-group cleanup."""
    process = None
    selector = None
    buffers: dict[Any, bytearray] = {}
    streams: set[Any] = set()
    timed_out = False
    truncated = False
    deadline = time.monotonic() + max(0.0, timeout)
    drain_deadline: float | None = None

    def terminate_group() -> None:
        if process is None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            elif process.poll() is None:
                process.kill()
        except (ProcessLookupError, PermissionError, OSError):
            if process.poll() is None:
                try:
                    process.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    pass

    def bounded_wait() -> int | None:
        if process is None:
            return None
        try:
            return process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            terminate_group()
            try:
                return process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                return process.poll()

    try:
        if not argv or max_output <= 0:
            raise ValueError("invalid child process bounds")
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(env) if env is not None else None, shell=False, close_fds=True,
            start_new_session=(os.name == "posix"),
        )
        selector = selectors.DefaultSelector()
        for stream in (process.stdout, process.stderr):
            selector.register(stream, selectors.EVENT_READ)
            buffers[stream] = bytearray()
            streams.add(stream)
        while streams or process.poll() is None:
            now = time.monotonic()
            if now >= deadline and not timed_out:
                timed_out = True
                terminate_group()
                drain_deadline = now + 0.5
            if timed_out and drain_deadline is not None and now >= drain_deadline:
                for stream in tuple(streams):
                    try:
                        selector.unregister(stream)
                    except Exception:
                        pass
                    streams.remove(stream)
                    stream.close()
                terminate_group()
                break
            if streams:
                stop = drain_deadline if timed_out else deadline
                interval = min(0.05, max(0.0, (stop or now) - now))
                events = selector.select(interval)
                for key, _ in events:
                    stream = key.fileobj
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        selector.unregister(stream)
                        streams.remove(stream)
                        stream.close()
                        continue
                    buf = buffers[stream]
                    available = max_output - len(buf)
                    if available > 0:
                        buf.extend(chunk[:available])
                    if len(chunk) > available:
                        truncated = True
            else:
                stop = drain_deadline if timed_out else deadline
                time.sleep(min(0.05, max(0.0, (stop or time.monotonic()) - time.monotonic())))
        code = bounded_wait()
        stdout = buffers[process.stdout].decode("utf-8", "replace")
        stderr = buffers[process.stderr].decode("utf-8", "replace")
        return _CommandResult(code, stdout, stderr, timed_out or code is None, truncated)
    except BaseException as exc:
        terminate_group()
        bounded_wait()
        if not isinstance(exc, Exception):
            raise
        raise LudusAdapterError("Ludus command could not be completed safely", 2, "unknown") from None
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def _execute(context: ResolvedContext, argv: tuple[str, ...], timeout: float = _TIMEOUT) -> _CommandResult:
    return _capture_process(_freeze_argv(context, argv), timeout, _MAX_OUTPUT, dict(context._env))


def _json_result(result: _CommandResult) -> Any:
    if result.timed_out or result.truncated or result.returncode != 0:
        raise LudusAdapterError("Ludus read failed or returned incomplete output", 2, "unknown")
    try:
        value = json.loads(result.stdout)
    except Exception:
        raise LudusAdapterError("Ludus returned an unsupported response", 2, "unknown") from None
    if not isinstance(value, (dict, list)):
        raise LudusAdapterError("Ludus returned an unsupported response", 2, "unknown")
    if isinstance(value, dict) and "error" in value:
        raise LudusAdapterError("Ludus rejected the request", 2, "unknown")
    return value


def _str_field(value: dict[str, Any], key: str, optional: bool = False) -> str | None:
    field_value = value.get(key)
    if optional and field_value is None:
        return None
    if not isinstance(field_value, str):
        raise LudusAdapterError("Ludus response shape is unsupported", 2, "unknown")
    return field_value


def _snapshot(data: Any, range_id: str, secrets: tuple[str, ...] = ()) -> models.RangeSnapshot:
    if not isinstance(data, dict) or data.get("rangeID") != range_id:
        raise LudusAdapterError("Ludus range status does not match the selected target", 2, "unknown")
    raw_state = _str_field(data, "rangeState")
    if _safe_metadata_text(raw_state, secrets) is None:
        raise LudusAdapterError("Ludus status metadata is unsupported", 2, "unknown")
    state = _validate_range_state(raw_state)
    last = _safe_metadata_text(_str_field(data, "lastDeployment"), secrets)
    if last is None:
        raise LudusAdapterError("Ludus status metadata is unsupported", 2, "unknown")
    testing = data.get("testingEnabled")
    if not isinstance(testing, bool):
        raise LudusAdapterError("Ludus response shape is unsupported", 2, "unknown")
    return models.RangeSnapshot(state, state in {"DEPLOYING", "DESTROYING"}, testing, None, None,
                               datetime.now(timezone.utc).isoformat())


def _history_metadata(item: Any, secrets: tuple[str, ...]) -> models.HistoryEntry:
    if not isinstance(item, dict):
        raise LudusAdapterError("Ludus history response is unsupported", 2, "unknown")
    history_id = _safe_history_id(_str_field(item, "id"), secrets)
    if history_id is None:
        raise LudusAdapterError("Ludus history metadata is unsupported", 2, "unknown")
    status = _str_field(item, "status")
    if _safe_metadata_text(status, secrets) is None:
        raise LudusAdapterError("Ludus history status is unsupported", 2, "unknown")
    if status not in {"running", "success", "failure", "aborted"}:
        raise LudusAdapterError("Ludus history status is unsupported", 2, "unknown")
    timestamps = []
    for key in ("start", "end", "created"):
        value = _str_field(item, key, True)
        if value is not None:
            safe = _safe_metadata_text(value, secrets)
            if safe is None or not _TIMESTAMP.fullmatch(safe):
                raise LudusAdapterError("Ludus history metadata is unsupported", 2, "unknown")
            try:
                datetime.fromisoformat(safe.replace("Z", "+00:00"))
            except ValueError:
                raise LudusAdapterError("Ludus history metadata is unsupported", 2, "unknown") from None
            value = safe
        timestamps.append(value)
    return models.HistoryEntry(history_id, status, *timestamps)


@dataclass(frozen=True, repr=False)
class BoundSession:
    target: models.Target
    read: "_ReadClient"
    _context: ResolvedContext | None = field(repr=False)
    _closed: bool = field(default=False, repr=False)
    _deploy_clients: list[Any] = field(default_factory=list, repr=False)

    def __reduce__(self):
        raise TypeError("bound Ludus session cannot be serialized")

    def close(self) -> None:
        object.__setattr__(self, "_closed", True)
        self.read._context = None
        for client in self._deploy_clients:
            client._context = None
        self._deploy_clients.clear()
        object.__setattr__(self, "_context", None)

    def validate_configured_roles(self, identities: tuple[str, ...]) -> None:
        """Reject configured identities containing credentials or unsafe text."""
        context = self._context
        if self._closed or context is None:
            raise LudusAdapterError("Ludus session is closed", 2, "blocked")
        secrets = context._secrets.values()
        if not isinstance(identities, (tuple, list)):
            raise LudusAdapterError("Configured role identities are unsupported", 2, "blocked")
        for identity in identities:
            if _safe_metadata_text(identity, secrets) is None:
                raise LudusAdapterError("Configured role identity contains unsafe data", 2, "blocked")

    def safe_missing_roles_message(self, error: Exception) -> str:
        """Render a structured source diagnostic without exposing registered secrets."""
        context = self._context
        if self._closed or context is None:
            return "Configured roles could not be resolved safely"
        from . import source

        if not isinstance(error, source.MissingRolesError):
            return "Configured roles could not be resolved safely"
        identities = tuple(error.identities)
        self.validate_configured_roles(identities)
        return source.safe_missing_roles_message(error, identities, context._secrets.values())

    def register_staged_secrets(self, roles: tuple[models.StagedRole, ...]) -> None:
        if self._closed or self._context is None:
            raise LudusAdapterError("Ludus session is closed", 2, "blocked")
        for role in roles:
            _register_role_secrets(self._context, role)

    def safe_resolution_evidence(self, role: models.StagedRole) -> tuple[str, ...]:
        """Screen snapshot metadata and fixed source provenance before retention."""
        from . import source
        from .state import sanitize

        context = self._context
        if self._closed or context is None:
            raise LudusAdapterError("Ludus session is closed", 2, "blocked")
        self.validate_configured_roles((role.role.identity,))
        author, metadata_name = source._metadata(role.directory)
        values = ("configured:" + role.role.identity, "source:" + str(role.role.source),
                  *tuple(item for item in role.role.resolution_evidence
                         if item in {"exact-folder", "explicit-mapping"}),
                  "metadata-author:" + author, "metadata-role-name:" + metadata_name)
        secrets = context._secrets.values()
        return tuple(sanitize(value, frozenset(secrets)) for value in values
                     if _safe_metadata_text(value, secrets) is not None)


class _ReadClient:
    def __init__(self, context: ResolvedContext, target: models.Target):
        self._context = context
        self._target = target

    def _run(self, template: tuple[str, ...]) -> _CommandResult:
        if not self._context:
            raise LudusAdapterError("Ludus session is closed", 2, "blocked")
        return _execute(self._context, _freeze_template(template, self._target.range_id))

    def active_config(self) -> str:
        value = _json_result(self._run(_active_config_argv()))
        if not isinstance(value, dict) or not isinstance(value.get("result"), str):
            raise LudusAdapterError("Ludus configuration response is unsupported", 2, "unknown")
        try:
            config = yaml.safe_load(value["result"])
        except Exception:
            raise LudusAdapterError("Ludus configuration response is unsupported", 2, "unknown") from None
        if not isinstance(config, dict):
            raise LudusAdapterError("Ludus configuration response is unsupported", 2, "unknown")
        _register_config_secrets(self._context, config)
        return value["result"]

    def status(self) -> models.RangeSnapshot:
        return _snapshot(_json_result(self._run(_status_argv())), self._target.range_id,
                         self._context._secrets.values())

    def installed_roles(self) -> frozenset[str]:
        rows = _json_result(self._run(_installed_roles_argv()))
        if not isinstance(rows, list):
            raise LudusAdapterError("Ludus role response is unsupported", 2, "unknown")
        names = set()
        for item in rows:
            if not isinstance(item, dict) or not isinstance(item.get("type"), str) or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
                raise LudusAdapterError("Ludus role response is unsupported", 2, "unknown")
            if item["type"] not in {"role", "collection"}:
                raise LudusAdapterError("Ludus role response is unsupported", 2, "unknown")
            safe_name = _safe_metadata_text(item["name"], self._context._secrets.values())
            safe_version = _safe_metadata_text(item["version"], self._context._secrets.values())
            if safe_name is None or not _ROLE_ID.fullmatch(safe_name) or safe_version is None:
                raise LudusAdapterError("Ludus role response is unsupported", 2, "unknown")
            global_flag = item.get("global", False)
            if not isinstance(global_flag, bool):
                raise LudusAdapterError("Ludus role response is unsupported", 2, "unknown")
            if item["type"] == "role" and not global_flag:
                names.add(safe_name)
        return frozenset(names)

    def history_list(self) -> tuple[models.HistoryEntry, ...]:
        rows = _json_result(self._run(_history_list_argv()))
        if not isinstance(rows, list):
            raise LudusAdapterError("Ludus history response is unsupported", 2, "unknown")
        entries = []
        for item in rows:
            entries.append(_history_metadata(item, self._context._secrets.values()))
        return tuple(entries)

    def observe_history(self, history_id: str) -> models.Observation:
        if self._context is None:
            return models.Observation(self._target, None, None, "user-selected", None, ())
        safe_id = _safe_history_id(history_id, self._context._secrets.values())
        if safe_id is None:
            return models.Observation(self._target, None, None, "user-selected", None, ())
        entries = self.history_list()
        matches = tuple(entry for entry in entries if entry.history_id == safe_id)
        if len(matches) != 1:
            return models.Observation(self._target, safe_id, None, "user-selected", None, ())
        entry = matches[0]
        return models.Observation(self._target, safe_id, entry.status, "user-selected", None, ())

    def observe_run(self, run: models.RunRecord) -> models.Observation:
        if run.target != self._target:
            raise LudusAdapterError("Recorded run target does not match the selected target", 2, "blocked")
        entries = self.history_list()
        return models.Observation(self._target, None, None, "unknown", self.status(), entries)


class DeployClient:
    def __init__(self, context: ResolvedContext, target: models.Target):
        self._context = context
        self._target = target

    def upload(self, role: models.StagedRole) -> models.UploadResult:
        if self._context is None:
            return models.UploadResult("failure", "Bound Ludus session is closed")
        if role.directory.name != role.role.identity:
            return models.UploadResult("failure", "Staged role identity does not match its directory")
        try:
            _register_role_secrets(self._context, role)
        except LudusAdapterError:
            return models.UploadResult("failure", "Staged role defaults cannot be safely inspected")
        result = _execute(self._context, _freeze_template(_upload_argv(), str(role.directory)), timeout=300)
        if result.timed_out or result.truncated or result.returncode != 0:
            return models.UploadResult("unknown", "Role upload outcome is unknown")
        try:
            value = json.loads(result.stdout)
        except Exception:
            return models.UploadResult("unknown", "Role upload outcome is unknown")
        return _classify_upload_response(value, returncode=result.returncode,
                                         timed_out=result.timed_out, truncated=result.truncated)

    def launch(self, scope: models.Scope) -> models.LaunchResult:
        if self._context is None:
            return models.LaunchResult(None, None)
        if scope not in {"roles", "full"}:
            return models.LaunchResult(None, None)
        template = _launch_roles_argv() if scope == "roles" else _launch_full_argv()
        result = _execute(self._context, _freeze_template(template, self._target.range_id), timeout=120)
        if result.timed_out or result.truncated or result.returncode != 0:
            return models.LaunchResult(None, None)
        try:
            value = json.loads(result.stdout)
        except Exception:
            return models.LaunchResult(None, None)
        if isinstance(value, dict) and value == {"result": "Range deploy started"}:
            return models.LaunchResult(True, None)
        return models.LaunchResult(None, None)


def _freeze_template(template: tuple[str, ...], value: str) -> tuple[str, ...]:
    return tuple(value if item in {"<range>", "<stage>"} else item for item in template)


def discover_target(range_id: str) -> BoundSession:
    range_id = _validate_range_id(range_id)
    context = resolve_context()
    try:
        client_ver = _execute(context, _client_version_argv())
        if client_ver.timed_out or client_ver.truncated or client_ver.returncode != 0:
            raise LudusAdapterError("Ludus client version could not be verified", 2, "blocked")
        server = _execute(context, _server_version_argv())
        if server.timed_out or server.truncated or server.returncode != 0:
            raise LudusAdapterError("Ludus server version could not be verified", 2, "blocked")
        _parse_versions(client_ver.stdout + "\n" + client_ver.stderr,
                        server.stdout + "\n" + server.stderr)
        caps = models.Capabilities(_SUPPORTED, _SUPPORTED, {}, "unknown-only")
        target = models.Target(models.ServerKey(context.endpoint, "user:" + context.effective_user), range_id, caps)
        reader = _ReadClient(context, target)
        # Both authenticated reads must succeed before prefix is treated as authenticated identity.
        reader.active_config()
        reader.installed_roles()
        return BoundSession(target, reader, context)
    except LudusAdapterError:
        raise
    except Exception:
        # Never propagate raw subprocess output or parser/config exceptions.
        raise LudusAdapterError("Ludus target discovery failed safely", 2, "unknown") from None


def enable_deploy(session: BoundSession) -> DeployClient:
    if not isinstance(session, BoundSession) or session._closed or session._context is None:
        raise LudusAdapterError("A live bound Ludus session is required", 2, "blocked")
    if session.read._context is not session._context or session.read._target != session.target:
        raise LudusAdapterError("Bound Ludus session target integrity check failed", 2, "blocked")
    client = DeployClient(session._context, session.target)
    session._deploy_clients.append(client)
    return client
