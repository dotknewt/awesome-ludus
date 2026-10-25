"""Value-free diagnostics for a failed protected kubernetes.core.helm task."""

import hashlib
import json
import os
import re
from collections.abc import Mapping

from ansible.plugins.action import ActionBase


FQCN = "kubernetes.core.helm"
COLLECTION = "kubernetes.core"
PROVENANCE = "post_failure_loader_snapshot"
EVALUATION_ERROR = "diagnostics_unavailable"
FAILURE_CONTEXT_UNAVAILABLE = "failure_context_unavailable"
COLLECTION_CONTEXT_UNAVAILABLE = "collection_context_unavailable"
UNSUPPORTED_PREFIXES = (
    "Unsupported parameters for (kubernetes.core.helm) module: ",
    "Unsupported parameters for (helm) module: ",
)
SUPPORTED_DELIMITER = ". Supported parameters include:"
HELM_COMMAND_PREFIX = "Failure when executing Helm command. Exited"
CHART_SCHEMA_MARKERS = (
    "values don't meet the specifications of the schema(s)",
    "values don't meet the specifications",
)
TEMPLATE_YAML_MARKERS = (
    "YAML parse error",
    "error converting YAML to JSON",
)
TIMEOUT_MARKERS = (
    "timed out waiting for the condition",
    "context deadline exceeded",
)
CLASSIFICATION_KEYS = (
    "helm_command_error",
    "unsupported_parameter",
    "reset_values_rejected",
    "chart_schema_marker",
    "template_yaml_marker",
    "timeout_marker",
    "unknown",
)
MAX_ERROR_TEXT = 65536
MAX_REJECTED_CLAUSE = 4096
MAX_PARAMETER_COUNT = 64
MAX_PARAMETER_LENGTH = 128
MAX_COLLECTIONS = 64
MAX_COLLECTION_LENGTH = 128
MAX_MODULE_PATH_LENGTH = 4096
MAX_MODULE_BYTES = 2000000
MAX_MANIFEST_BYTES = 1000000
MAX_VERSION_LENGTH = 128
COLLECTION_ID_PATTERN = r"[A-Za-z0-9_]+\.[A-Za-z0-9_-]+"
PARAMETER_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"
VERSION_PATTERN = r"[A-Za-z0-9][A-Za-z0-9.+_-]*"
MODULE_SUFFIX = os.path.join("kubernetes", "core", "plugins", "modules", "helm.py")
MODULE_RELATIVE_PATH = os.path.join("plugins", "modules", "helm.py")


def _parse_unsupported_parameters(message):
    if not isinstance(message, str):
        return None

    for prefix in UNSUPPORTED_PREFIXES:
        if not message.startswith(prefix):
            continue
        remainder = message[len(prefix):]
        if len(remainder) > MAX_ERROR_TEXT:
            return None
        pieces = remainder.split(SUPPORTED_DELIMITER, 1)
        if len(pieces) != 2:
            return None
        rejected_clause = pieces[0]
        if len(rejected_clause) > MAX_REJECTED_CLAUSE:
            return None
        raw_tokens = rejected_clause.split(",")
        if not raw_tokens or len(raw_tokens) > MAX_PARAMETER_COUNT:
            return None
        tokens = []
        for raw_token in raw_tokens:
            token = raw_token.strip()
            if (not token or len(token) > MAX_PARAMETER_LENGTH
                    or re.fullmatch(PARAMETER_PATTERN, token, flags=re.ASCII) is None):
                return None
            tokens.append(token)
        return tuple(tokens)
    return None


def _empty_classification(unknown):
    return {
        "helm_command_error": False,
        "unsupported_parameter": False,
        "reset_values_rejected": False,
        "chart_schema_marker": False,
        "template_yaml_marker": False,
        "timeout_marker": False,
        "unknown": unknown,
    }


def _classify_messages(message, stderr):
    result = _empty_classification(True)
    recognized_format = False
    strings = []
    for value in (message, stderr):
        if isinstance(value, str) and len(value) <= MAX_ERROR_TEXT:
            strings.append(value)

    for text in strings:
        if text.startswith(HELM_COMMAND_PREFIX):
            result["helm_command_error"] = True
            recognized_format = True

        rejected_parameters = _parse_unsupported_parameters(text)
        if rejected_parameters is not None:
            result["unsupported_parameter"] = True
            if "reset_values" in rejected_parameters:
                result["reset_values_rejected"] = True
            recognized_format = True

        if any(marker in text for marker in CHART_SCHEMA_MARKERS):
            result["chart_schema_marker"] = True
        if any(marker in text for marker in TEMPLATE_YAML_MARKERS):
            result["template_yaml_marker"] = True
        if any(marker in text for marker in TIMEOUT_MARKERS):
            result["timeout_marker"] = True

    result["unknown"] = not recognized_format
    return result


def _validated_collection_list(value):
    if not isinstance(value, list) or len(value) > MAX_COLLECTIONS:
        return None
    for collection_name in value:
        if (not isinstance(collection_name, str)
                or not collection_name
                or len(collection_name) > MAX_COLLECTION_LENGTH
                or re.fullmatch(COLLECTION_ID_PATTERN, collection_name, flags=re.ASCII) is None):
            return None
    return value


def _contains_control(value):
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _read_bounded(path, maximum_bytes):
    size = os.path.getsize(path)
    if size < 0 or size > maximum_bytes:
        raise ValueError
    with open(path, "rb") as source_file:
        contents = source_file.read(maximum_bytes + 1)
    if len(contents) > maximum_bytes:
        raise ValueError
    return contents


def _metadata_report(status, collections_context):
    return {
        "fqcn": FQCN,
        "provenance": PROVENANCE,
        "collections_context": collections_context,
        "status": status,
    }


class ActionModule(ActionBase):
    _requires_connection = False

    def _metadata_snapshot(self, failed_task):
        collections_context = "failed_task_collections"
        validated_collections = None
        if isinstance(failed_task, Mapping):
            validated_collections = _validated_collection_list(failed_task.get("collections"))

        if validated_collections is None:
            collections_context = "rescue_task_collections"
            validated_collections = _validated_collection_list(self._task.collections)
        if validated_collections is None:
            return _metadata_report("unresolved", COLLECTION_CONTEXT_UNAVAILABLE)

        try:
            loader_context = self._shared_loader_obj.module_loader.find_plugin_with_context(
                FQCN,
                collection_list=validated_collections,
            )
        except Exception:
            return _metadata_report("metadata_error", collections_context)

        if not getattr(loader_context, "resolved", False):
            return _metadata_report("unresolved", collections_context)
        if (getattr(loader_context, "resolved_fqcn", None) != FQCN
                or getattr(loader_context, "plugin_resolved_collection", None) != COLLECTION):
            return _metadata_report("unexpected_identity", collections_context)

        module_path = getattr(loader_context, "plugin_resolved_path", None)
        if (not isinstance(module_path, str) or not module_path
                or len(module_path) > MAX_MODULE_PATH_LENGTH
                or _contains_control(module_path)):
            return _metadata_report("unexpected_layout", collections_context)

        try:
            normalized_module_path = os.path.normpath(os.path.abspath(module_path))
            suffix = os.sep + MODULE_SUFFIX
            if not normalized_module_path.endswith(suffix):
                return _metadata_report("unexpected_layout", collections_context)
            collection_root = os.path.dirname(os.path.dirname(os.path.dirname(normalized_module_path)))
            collection_root_realpath = os.path.realpath(collection_root)
            module_realpath = os.path.realpath(normalized_module_path)
            if any(len(path) > MAX_MODULE_PATH_LENGTH or _contains_control(path)
                   for path in (collection_root_realpath, module_realpath)):
                return _metadata_report("unexpected_layout", collections_context)
            if (not os.path.isabs(collection_root_realpath)
                    or not os.path.isabs(module_realpath)
                    or os.path.commonpath((collection_root_realpath, module_realpath))
                    != collection_root_realpath
                    or os.path.relpath(module_realpath, collection_root_realpath) != MODULE_RELATIVE_PATH):
                return _metadata_report("unexpected_layout", collections_context)

            manifest_path = os.path.join(collection_root_realpath, "MANIFEST.json")
            manifest_realpath = os.path.realpath(manifest_path)
            if (os.path.commonpath((collection_root_realpath, manifest_realpath))
                    != collection_root_realpath):
                return _metadata_report("unexpected_layout", collections_context)

            module_bytes = _read_bounded(module_realpath, MAX_MODULE_BYTES)
            manifest_bytes = _read_bounded(manifest_realpath, MAX_MANIFEST_BYTES)
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except Exception:
            return _metadata_report("metadata_error", collections_context)

        if not isinstance(manifest, Mapping):
            return _metadata_report("unexpected_identity", collections_context)
        collection_info = manifest.get("collection_info")
        if (not isinstance(collection_info, Mapping)
                or collection_info.get("namespace") != "kubernetes"
                or collection_info.get("name") != "core"):
            return _metadata_report("unexpected_identity", collections_context)

        version = collection_info.get("version")
        if (not isinstance(version, str) or not version
                or len(version) > MAX_VERSION_LENGTH
                or _contains_control(version)
                or re.fullmatch(VERSION_PATTERN, version, flags=re.ASCII) is None):
            return _metadata_report("unexpected_identity", collections_context)

        report = _metadata_report("available", collections_context)
        report.update({
            "module_path": normalized_module_path,
            "module_realpath": module_realpath,
            "version": version,
            "sha256": hashlib.sha256(module_bytes).hexdigest(),
        })
        return report

    def run(self, tmp=None, task_vars=None):
        if self._task.args:
            return {"failed": True, "msg": EVALUATION_ERROR}

        failed_result = None
        failed_task = None
        failure_context = "failure_context_unavailable"
        if isinstance(task_vars, Mapping):
            candidate_result = task_vars.get("ansible_failed_result")
            candidate_task = task_vars.get("ansible_failed_task")
            if isinstance(candidate_result, Mapping) and isinstance(candidate_task, Mapping):
                action = candidate_task.get("action")
                if isinstance(action, str) and action == FQCN:
                    failed_result = candidate_result
                    failed_task = candidate_task
                    failure_context = "available"

        try:
            if failed_result is None:
                classification = _empty_classification(True)
            else:
                message = failed_result.get("msg")
                stderr = failed_result.get("stderr")
                if not isinstance(message, str):
                    message = None
                if not isinstance(stderr, str):
                    stderr = None
                classification = _classify_messages(message, stderr)
        except Exception:
            classification = _empty_classification(True)

        try:
            metadata = self._metadata_snapshot(failed_task)
        except Exception:
            metadata = _metadata_report("metadata_error", COLLECTION_CONTEXT_UNAVAILABLE)

        return {
            "changed": False,
            "report": {
                "failure_context": failure_context,
                "classification": classification,
                "metadata": metadata,
            },
        }
