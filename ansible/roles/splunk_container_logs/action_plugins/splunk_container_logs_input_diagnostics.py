"""Value-free controller diagnostics for shared HEC input validation."""

from ansible.playbook.conditional import Conditional
from ansible.plugins.action import ActionBase


EVALUATION_ERROR = "evaluation_error"

CONDITION_CATALOGUE = (
    ("owner_id_type", "splunk_container_logs_owner_id is string"),
    ("owner_id_nonempty", "splunk_container_logs_owner_id | length > 0"),
    ("owner_id_pattern", "splunk_container_logs_owner_id is match('^[A-Za-z0-9][A-Za-z0-9._-]*$')"),
    ("hec_endpoint_type", "splunk_container_logs_hec_endpoint is string"),
    ("hec_endpoint_nonempty", "splunk_container_logs_hec_endpoint | length > 0"),
    ("hec_endpoint_hostname", "splunk_container_logs_hec_endpoint | urlsplit('hostname') | length > 0"),
    ("hec_endpoint_path", "splunk_container_logs_hec_endpoint | urlsplit('path') == '/services/collector/event'"),
    ("hec_endpoint_no_query", "splunk_container_logs_hec_endpoint | urlsplit('query') | length == 0"),
    ("hec_endpoint_no_fragment", "splunk_container_logs_hec_endpoint | urlsplit('fragment') | length == 0"),
    ("hec_endpoint_no_username", "splunk_container_logs_hec_endpoint | urlsplit('username') is none"),
    ("hec_endpoint_no_password", "splunk_container_logs_hec_endpoint | urlsplit('password') is none"),
    ("hec_endpoint_scheme", "splunk_container_logs_hec_endpoint.startswith('https://') or (splunk_container_logs_hec_endpoint.startswith('http://') and splunk_container_logs_allow_insecure_http)"),
    ("hec_index_type", "splunk_container_logs_hec_index is string"),
    ("hec_index_nonempty", "splunk_container_logs_hec_index | length > 0"),
    ("hec_token_type", "splunk_container_logs_hec_token is string"),
    ("hec_token_or_secret", "splunk_container_logs_hec_token | length > 0 or (splunk_container_logs_mode == 'kubernetes' and splunk_container_logs_k8s_existing_secret | length > 0)"),
    ("tls_verify_boolean", "splunk_container_logs_tls_verify is boolean"),
    ("allow_insecure_http_boolean", "splunk_container_logs_allow_insecure_http is boolean"),
    ("ca_file_type", "splunk_container_logs_ca_file is string"),
    ("start_at_allowed", "splunk_container_logs_start_at in ['end', 'beginning']"),
    ("queue_size_valid", "(splunk_container_logs_queue_size | splunk_container_queue_size) is integer"),
    ("queue_disk_valid", "(splunk_container_logs_queue_max_disk_mib | splunk_container_queue_disk_mib) is integer"),
    ("collector_url_for_docker", "splunk_container_logs_mode != 'docker' or (splunk_container_logs_collector_url is string and splunk_container_logs_collector_url.startswith('https://'))"),
)

KUBERNETES_CONDITION_CATALOGUE = (
    ("kubeconfig_string", "splunk_container_logs_kubeconfig is string"),
    ("kubeconfig_nonempty", "splunk_container_logs_kubeconfig | length > 0"),
    ("kube_context_string", "splunk_container_logs_kube_context is string"),
    ("kube_context_nonempty", "splunk_container_logs_kube_context | length > 0"),
    ("cluster_name_string", "splunk_container_logs_k8s_cluster_name is string"),
    ("cluster_name_nonempty", "splunk_container_logs_k8s_cluster_name | length > 0"),
    ("namespace_dns_label", "splunk_container_logs_k8s_namespace is match('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')"),
    ("release_dns_label", "splunk_container_logs_k8s_release is match('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')"),
    ("existing_secret_string", "splunk_container_logs_k8s_existing_secret is string"),
    ("existing_secret_empty_or_name", "splunk_container_logs_k8s_existing_secret | length == 0 or splunk_container_logs_k8s_existing_secret is match('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')"),
    ("secret_excludes_token", "splunk_container_logs_k8s_existing_secret | length == 0 or splunk_container_logs_hec_token | length == 0"),
    ("secret_excludes_ca_file", "splunk_container_logs_k8s_existing_secret | length == 0 or splunk_container_logs_ca_file | length == 0"),
    ("node_selector_mapping", "splunk_container_logs_k8s_node_selector is mapping"),
    ("node_selector_nonempty", "splunk_container_logs_k8s_node_selector | length > 0"),
    ("node_selector_os_linux", "splunk_container_logs_k8s_node_selector.get('kubernetes.io/os', 'linux') == 'linux'"),
    ("node_selector_arch_amd64", "splunk_container_logs_k8s_node_selector.get('kubernetes.io/arch', 'amd64') == 'amd64'"),
    ("tolerations_sequence", "splunk_container_logs_k8s_tolerations is sequence"),
    ("tolerations_not_string", "splunk_container_logs_k8s_tolerations is not string"),
    ("log_paths_sequence", "splunk_container_logs_k8s_log_paths is sequence"),
    ("log_paths_not_string", "splunk_container_logs_k8s_log_paths is not string"),
    ("log_paths_nonempty", "splunk_container_logs_k8s_log_paths | length > 0"),
    ("log_paths_unique", "splunk_container_logs_k8s_log_paths | unique | length == splunk_container_logs_k8s_log_paths | length"),
    ("log_paths_include_pods", "'/var/log/pods' in splunk_container_logs_k8s_log_paths"),
    ("log_paths_supported_roots", "splunk_container_logs_k8s_log_paths | difference(['/var/log/pods', '/var/log/containers']) | length == 0"),
    ("persistent_paths_valid", "[splunk_container_logs_k8s_checkpoint_path, splunk_container_logs_k8s_queue_path] | splunk_k8s_persistent_paths_valid"),
    ("chart_url_string", "splunk_container_logs_chart_url is string"),
    ("chart_url_https", "splunk_container_logs_chart_url.startswith('https://')"),
)

TYPE_VARIABLES = (
    "splunk_container_logs_owner_id",
    "splunk_container_logs_hec_endpoint",
    "splunk_container_logs_hec_index",
    "splunk_container_logs_hec_token",
    "splunk_container_logs_mode",
    "splunk_container_logs_k8s_existing_secret",
    "splunk_container_logs_tls_verify",
    "splunk_container_logs_allow_insecure_http",
    "splunk_container_logs_ca_file",
    "splunk_container_logs_start_at",
    "splunk_container_logs_queue_size",
    "splunk_container_logs_queue_max_disk_mib",
    "splunk_container_logs_collector_url",
)

KUBERNETES_TYPE_VARIABLES = (
    "splunk_container_logs_kubeconfig",
    "splunk_container_logs_kube_context",
    "splunk_container_logs_k8s_cluster_name",
    "splunk_container_logs_k8s_namespace",
    "splunk_container_logs_k8s_release",
    "splunk_container_logs_k8s_existing_secret",
    "splunk_container_logs_hec_token",
    "splunk_container_logs_ca_file",
    "splunk_container_logs_k8s_node_selector",
    "splunk_container_logs_k8s_tolerations",
    "splunk_container_logs_k8s_log_paths",
    "splunk_container_logs_k8s_checkpoint_path",
    "splunk_container_logs_k8s_queue_path",
    "splunk_container_logs_chart_url",
)

TYPE_CODES = {
    "str": "text",
    "AnsibleUnsafeText": "unsafe_text",
    "AnsibleUnicode": "unicode_text",
    "bool": "boolean",
    "int": "integer",
    "float": "float",
    "list": "list",
    "dict": "mapping",
    "NoneType": "null",
    "tuple": "tuple",
    "set": "set",
    "AnsibleSequence": "sequence",
    "AnsibleMapping": "mapping",
    "AnsibleVaultEncryptedUnicode": "vault_text",
    "AnsibleUndefined": "undefined",
}


class ActionModule(ActionBase):
    _requires_connection = False

    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        if args == {}:
            catalogue = CONDITION_CATALOGUE
            type_variables = TYPE_VARIABLES
        elif args == {"contract": "kubernetes"}:
            catalogue = KUBERNETES_CONDITION_CATALOGUE
            type_variables = KUBERNETES_TYPE_VARIABLES
        else:
            return {"failed": True, "msg": EVALUATION_ERROR}

        if task_vars is None:
            return {"failed": True, "msg": EVALUATION_ERROR}

        predicate_rows = []
        for name, expression in catalogue:
            try:
                conditional = Conditional(loader=self._loader)
                conditional.when = [expression]
                result = conditional.evaluate_conditional(
                    templar=self._templar,
                    all_vars=task_vars,
                )
                if type(result) is not bool:
                    result = EVALUATION_ERROR
            except Exception:
                result = EVALUATION_ERROR

            predicate_rows.append({
                "name": name,
                "result": result,
            })

        input_type_rows = []
        templar = self._templar
        previous_variables = templar.available_variables
        try:
            templar.available_variables = task_vars
            for variable in type_variables:
                expression = "{{ " + variable + " | type_debug }}"
                try:
                    detected_type = templar.template(expression)
                    code = TYPE_CODES.get(detected_type, "other")
                except Exception:
                    code = EVALUATION_ERROR
                input_type_rows.append({"name": variable, "type": code})
        finally:
            templar.available_variables = previous_variables

        return {
            "changed": False,
            "report": {
                "predicates": predicate_rows,
                "input_types": input_type_rows,
            },
        }
