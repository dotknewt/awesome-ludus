"""Fixed schemas for the three safe report publications in the role."""
import re

PROFILE_TASKS = {
    "shared_input": "splunk_container_logs : Publish the sanitized shared HEC input diagnostic report",
    "kubernetes_input": "splunk_container_logs : Publish the sanitized Kubernetes input diagnostic report",
    "helm": "splunk_container_logs : Publish only the safe Helm failure report",
}
PREDICATES = {
    "shared": ("owner_id_type", "owner_id_nonempty", "owner_id_pattern", "hec_endpoint_type", "hec_endpoint_nonempty", "hec_endpoint_hostname", "hec_endpoint_path", "hec_endpoint_no_query", "hec_endpoint_no_fragment", "hec_endpoint_no_username", "hec_endpoint_no_password", "hec_endpoint_scheme", "hec_index_type", "hec_index_nonempty", "hec_token_type", "hec_token_or_secret", "tls_verify_boolean", "allow_insecure_http_boolean", "ca_file_type", "start_at_allowed", "queue_size_valid", "queue_disk_valid", "collector_url_for_docker"),
    "kubernetes": ("kubeconfig_string", "kubeconfig_nonempty", "kube_context_string", "kube_context_nonempty", "cluster_name_string", "cluster_name_nonempty", "namespace_dns_label", "release_dns_label", "existing_secret_string", "existing_secret_empty_or_name", "secret_excludes_token", "secret_excludes_ca_file", "node_selector_mapping", "node_selector_nonempty", "node_selector_os_linux", "node_selector_arch_amd64", "tolerations_sequence", "tolerations_not_string", "log_paths_sequence", "log_paths_not_string", "log_paths_nonempty", "log_paths_unique", "log_paths_include_pods", "log_paths_supported_roots", "persistent_paths_valid", "chart_url_string", "chart_url_https"),
}
TYPE_VARIABLES = {
    "shared": ("splunk_container_logs_owner_id", "splunk_container_logs_hec_endpoint", "splunk_container_logs_hec_index", "splunk_container_logs_hec_token", "splunk_container_logs_mode", "splunk_container_logs_k8s_existing_secret", "splunk_container_logs_tls_verify", "splunk_container_logs_allow_insecure_http", "splunk_container_logs_ca_file", "splunk_container_logs_start_at", "splunk_container_logs_queue_size", "splunk_container_logs_queue_max_disk_mib", "splunk_container_logs_collector_url"),
    "kubernetes": ("splunk_container_logs_kubeconfig", "splunk_container_logs_kube_context", "splunk_container_logs_k8s_cluster_name", "splunk_container_logs_k8s_namespace", "splunk_container_logs_k8s_release", "splunk_container_logs_k8s_existing_secret", "splunk_container_logs_hec_token", "splunk_container_logs_ca_file", "splunk_container_logs_k8s_node_selector", "splunk_container_logs_k8s_tolerations", "splunk_container_logs_k8s_log_paths", "splunk_container_logs_k8s_checkpoint_path", "splunk_container_logs_k8s_queue_path", "splunk_container_logs_chart_url"),
}
TYPE_CODES = frozenset({"text", "unsafe_text", "unicode_text", "boolean", "integer", "float", "list", "mapping", "null", "tuple", "set", "sequence", "vault_text", "undefined", "other", "evaluation_error"})
HELM_CLASSIFICATIONS = ("helm_command_error", "unsupported_parameter", "reset_values_rejected", "chart_schema_marker", "template_yaml_marker", "timeout_marker", "unknown")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}\Z", re.ASCII)
_SHA = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_MODULE_SUFFIX = "/kubernetes/core/plugins/modules/helm.py"
_MODULE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z", re.ASCII)


def validate(profile, value):
    if not isinstance(value, dict):
        return None
    if profile in ("shared_input", "kubernetes_input"):
        key = "shared" if profile == "shared_input" else "kubernetes"
        if set(value) != {"predicates", "input_types"}:
            return None
        predicates = value["predicates"]
        input_types = value["input_types"]
        if not isinstance(predicates, list) or not isinstance(input_types, list):
            return None
        expected_predicates = PREDICATES[key]
        expected_types = TYPE_VARIABLES[key]
        if len(predicates) != len(expected_predicates) or len(input_types) != len(expected_types):
            return None
        for row, name in zip(predicates, expected_predicates):
            if (not isinstance(row, dict) or set(row) != {"name", "result"}
                    or row["name"] != name
                    or (type(row["result"]) is not bool and row["result"] != "evaluation_error")):
                return None
        for row, name in zip(input_types, expected_types):
            if (not isinstance(row, dict) or set(row) != {"name", "type"}
                    or row["name"] != name or not isinstance(row["type"], str)
                    or row["type"] not in TYPE_CODES):
                return None
        return value
    if profile != "helm" or set(value) != {"failure_context", "classification", "metadata"}:
        return None
    if not isinstance(value["failure_context"], str) or value["failure_context"] not in {"available", "failure_context_unavailable"}:
        return None
    classification = value["classification"]
    if (not isinstance(classification, dict) or set(classification) != set(HELM_CLASSIFICATIONS)
            or any(type(flag) is not bool for flag in classification.values())):
        return None
    metadata = value["metadata"]
    if not isinstance(metadata, dict):
        return None
    if metadata.get("fqcn") != "kubernetes.core.helm" or metadata.get("provenance") != "post_failure_loader_snapshot":
        return None
    state = metadata.get("status")
    if not isinstance(state, str):
        return None
    base = {"fqcn", "provenance", "collections_context", "status"}
    if state not in {"available", "unresolved", "metadata_error", "unexpected_identity", "unexpected_layout"}:
        return None
    context = metadata.get("collections_context")
    if not isinstance(context, str) or context not in {"failed_task_collections", "rescue_task_collections", "collection_context_unavailable"}:
        return None
    if state != "available":
        if set(metadata) != base:
            return None
        return value
    if set(metadata) != base | {"module_path", "module_realpath", "version", "sha256"}:
        return None
    module_path = metadata["module_path"]
    realpath = metadata["module_realpath"]
    version = metadata["version"]
    if (not isinstance(module_path, str) or not isinstance(realpath, str)
            or len(module_path) > 4096 or len(realpath) > 4096
            or not _MODULE_PATH.fullmatch(module_path) or not _MODULE_PATH.fullmatch(realpath)
            or any(ord(char) < 32 or ord(char) >= 127 for char in module_path + realpath)
            or any(part in {".", ".."} for part in module_path.split("/"))
            or any(part in {".", ".."} for part in realpath.split("/"))
            or not module_path.endswith(_MODULE_SUFFIX) or not realpath.endswith(_MODULE_SUFFIX)
            or not isinstance(version, str) or not _VERSION.fullmatch(version)
            or not isinstance(metadata["sha256"], str) or not _SHA.fullmatch(metadata["sha256"])):
        return None
    return value
