"""Explicit-path W2/W3 checks. Regex checks are superficial source contracts;
they do not prove ordering, guards, native behavior, or AD/SYSVOL semantics."""
from pathlib import Path
import re
import sys
import unittest
import yaml

REQUIRED = {"defaults/main.yml", "meta/main.yml", "LICENSE", "README.md",
            "files/LoggingPolicyState.ps1", "tasks/main.yml", "tasks/policy.yml",
            "files/Invoke-LoggingPolicy.ps1", "files/Publish-LoggingAudit.ps1",
            "templates/audit.csv.j2"}

CONFIGURATION_KEYS = {
    "domain", "server", "owner_id", "management_host", "state_dir",
    "logging_enabled", "enrollment_enabled", "defender_disable_policy_enabled",
    "names", "links", "audit_subcategories", "powershell", "enrollment", "defender",
    "execution_inventory_host", "desired_audit_csv",
}

AUDIT_GUIDS = [
    "{0cce9242-69ae-11d9-bed3-505054503030}", "{0cce9240-69ae-11d9-bed3-505054503030}",
    "{0cce9236-69ae-11d9-bed3-505054503030}", "{0cce9237-69ae-11d9-bed3-505054503030}",
    "{0cce9235-69ae-11d9-bed3-505054503030}", "{0cce923e-69ae-11d9-bed3-505054503030}",
    "{0cce923b-69ae-11d9-bed3-505054503030}", "{0cce923c-69ae-11d9-bed3-505054503030}",
    "{0cce923d-69ae-11d9-bed3-505054503030}", "{0cce9215-69ae-11d9-bed3-505054503030}",
    "{0cce921c-69ae-11d9-bed3-505054503030}", "{0cce921b-69ae-11d9-bed3-505054503030}",
    "{0cce9221-69ae-11d9-bed3-505054503030}", "{0cce9244-69ae-11d9-bed3-505054503030}",
    "{0cce9227-69ae-11d9-bed3-505054503030}",
]

SUPPORTED_AUDIT_PREFIXES = """
0cce9213 0cce9212 0cce9211 0cce9210 0cce9214 0cce9243 0cce921c 0cce921b
0cce921a 0cce9219 0cce9218 0cce9217 0cce9216 0cce9215 0cce9223 0cce9244
0cce9227 0cce9226 0cce9225 0cce9224 0cce9222 0cce9221 0cce9220 0cce921f
0cce921e 0cce921d 0cce9229 0cce922a 0cce9228 0cce922d 0cce922c 0cce922b
0cce922e 0cce9232 0cce9234 0cce9233 0cce922f 0cce9231 0cce9230 0cce923a
0cce9239 0cce9238 0cce9237 0cce9236 0cce9235 0cce923e 0cce923b 0cce923d
0cce923c 0cce9241 0cce9240 0cce923f 0cce9242 0cce9245 0cce9246 0cce9247
0cce9248 0cce9249
""".split()

EXPECTED_DEFAULTS = {
    "windows_logging_policy_domain": "",
    "windows_logging_policy_server": "",
    "windows_logging_policy_owner_id": "ludus-windows-logging-policy",
    "windows_logging_policy_management_host": "",
    "windows_logging_policy_state_dir": r"C:\ProgramData\Ludus\WindowsLoggingPolicy",
    "windows_logging_policy_logging_enabled": False,
    "windows_logging_policy_enrollment_enabled": False,
    "windows_logging_policy_defender_disable_policy_enabled": False,
    "windows_logging_policy_names": {"logging": "Ludus-Logging",
                                     "enrollment": "Ludus-CertEnroll",
                                     "defender": "Ludus-DisableDefender"},
    "windows_logging_policy_links": {"logging": [], "enrollment": [], "defender": []},
    "windows_logging_policy_audit_subcategories": [
        {"guid": guid, "success": True, "failure": True}
        for guid in AUDIT_GUIDS
    ],
    "windows_logging_policy_powershell": {"module_logging_enabled": True,
        "module_names": ["*"], "script_block_logging_enabled": True,
        "script_block_invocation_logging_enabled": True, "transcription_enabled": True,
        "transcription_invocation_header": True, "transcription_directory": r"C:\Transcripts"},
    "windows_logging_policy_enrollment": {"renew_update_revoke": True,
        "update_templates": True, "offline_expiration_percent": 10,
        "offline_expiration_store": "MY"},
    "windows_logging_policy_defender": {"disable_antispyware": True,
                                        "disable_realtime_monitoring": True},
}


def logical_name(path):
    value = path.as_posix().rstrip("/")
    return next((name for name in REQUIRED
                 if value == name or value.endswith(f"/{name}")), None)


class Artifacts:
    def __init__(self, arguments):
        self.paths = {}
        self.errors = []
        for argument in arguments:
            path = Path(argument)
            name = logical_name(path)
            if name is None:
                self.errors.append(f"unrecognized explicit artifact path: {argument}")
            elif name in self.paths:
                self.errors.append(f"duplicate explicit artifact path: {name}")
            else:
                self.paths[name] = path

    def read(self, case, name):
        case.assertFalse(self.errors, "Malformed harness input: " + "; ".join(self.errors))
        case.assertIn(name, self.paths, f"Missing explicit input path: {name}")
        path = self.paths[name]
        case.assertTrue(path.is_file(), f"Missing required W2/W3 implementation artifact: {name} ({path})")
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            case.fail(f"Malformed UTF-8 in {name}: {exc}")
        except OSError as exc:
            case.fail(f"Unable to read {name}: {exc}")

    def yaml(self, case, name):
        try:
            value = yaml.safe_load(self.read(case, name))
        except yaml.YAMLError as exc:
            case.fail(f"Malformed YAML in {name}: {exc}")
        case.assertIsInstance(value, dict, f"Malformed {name}: expected a YAML mapping")
        return value

    def yaml_list(self, case, name):
        try:
            value = yaml.safe_load(self.read(case, name))
        except yaml.YAMLError as exc:
            case.fail(f"Malformed YAML in {name}: {exc}")
        case.assertIsInstance(value, list, f"Malformed {name}: expected a YAML task list")
        return value


ARTIFACTS = Artifacts(sys.argv[1:])
sys.argv[1:] = []


def assert_strict(case, actual, expected, location="defaults"):
    case.assertIs(type(actual), type(expected), f"wrong type at {location}")
    if isinstance(expected, dict):
        case.assertEqual(set(actual), set(expected), f"wrong keys at {location}")
        for key in expected:
            assert_strict(case, actual[key], expected[key], f"{location}.{key}")
    elif isinstance(expected, list):
        case.assertEqual(len(actual), len(expected), f"wrong length at {location}")
        for index, pair in enumerate(zip(actual, expected)):
            assert_strict(case, pair[0], pair[1], f"{location}[{index}]")
    else:
        case.assertEqual(actual, expected, f"wrong value at {location}")


def function_block(case, source, name):
    match = re.search(rf"(?im)^\s*function\s+{re.escape(name)}\s*\{{", source)
    case.assertIsNotNone(match, f"missing public function {name}")
    following = re.search(r"(?im)^\s*function\s+[\w-]+\s*\{", source[match.end():])
    end = match.end() + following.start() if following else len(source)
    return source[match.start():end]


def assert_order(case, source, labels):
    position = -1
    for label, pattern in labels:
        match = re.search(pattern, source[position + 1:], re.I | re.S)
        case.assertIsNotNone(match, f"missing ordered phase: {label}")
        position += match.start() + 1


class PolicyContractStatic(unittest.TestCase):
    def test_required_explicit_artifacts_exist(self):
        for name in sorted(REQUIRED):
            ARTIFACTS.read(self, name)

    def test_defaults_have_exact_schema_values_and_types(self):
        assert_strict(self, ARTIFACTS.yaml(self, "defaults/main.yml"), EXPECTED_DEFAULTS)

    def test_default_policy_safety_is_explicit(self):
        defaults = ARTIFACTS.yaml(self, "defaults/main.yml")
        enabled = [
            "windows_logging_policy_logging_enabled",
            "windows_logging_policy_enrollment_enabled",
            "windows_logging_policy_defender_disable_policy_enabled",
        ]
        self.assertTrue(all(defaults.get(name) is False for name in enabled))
        self.assertEqual(defaults.get("windows_logging_policy_links"), {
            "logging": [], "enrollment": [], "defender": [],
        })
        self.assertEqual(len(defaults["windows_logging_policy_audit_subcategories"]), 15)
        self.assertEqual(set(defaults), set(EXPECTED_DEFAULTS),
                         "extra defaults, including a second Defender opt-in, are forbidden")

    def test_metadata_and_license_artifacts(self):
        galaxy = ARTIFACTS.yaml(self, "meta/main.yml").get("galaxy_info")
        self.assertIsInstance(galaxy, dict)
        self.assertEqual(galaxy.get("role_name"), "windows_logging_policy")
        self.assertEqual(galaxy.get("author"), "dotknewt")
        self.assertTrue(ARTIFACTS.read(self, "LICENSE").strip(), "LICENSE must not be empty")

    def test_public_helper_declarations_and_typed_parameters(self):
        source = ARTIFACTS.read(self, "files/LoggingPolicyState.ps1")
        contracts = {
            "Get-LoggingPolicyContext": [("hashtable", "Configuration")],
            "Enter-LoggingPolicyWriter": [("hashtable", "Context"), ("bool", "PlanOnly")],
            "Write-LoggingPolicyState": [("hashtable", "Context"), ("hashtable", "State")],
        }
        for function, parameters in contracts.items():
            declaration = re.search(rf"(?im)^\s*function\s+{re.escape(function)}\s*\{{", source)
            self.assertIsNotNone(declaration, f"missing public function {function}")
            nearby = source[declaration.start():declaration.start() + 1200]
            for kind, name in parameters:
                self.assertRegex(nearby, rf"(?i)\[{kind}\]\s*\${name}\b",
                                 f"{function} missing [{kind}] ${name}")

    def test_helper_has_no_obvious_out_of_scope_mutation_commands(self):
        source = ARTIFACTS.read(self, "files/LoggingPolicyState.ps1")
        forbidden = (
            "New-GPO", "Remove-GPO", "Set-GPRegistryValue", "Remove-GPRegistryValue",
            "New-GPLink", "Set-GPLink", "Remove-GPLink", "Set-ADObject",
            "New-ADObject", "Remove-ADObject", "auditpol", "Enable-WSManCredSSP",
            "Invoke-Expression",
        )
        for command in forbidden:
            self.assertNotRegex(source, rf"(?im)^(?!\s*#)[^\r\n#]*\b{re.escape(command)}\b",
                                f"superficial check found forbidden W2 command {command}")

    def test_helper_retains_required_guard_families(self):
        source = ARTIFACTS.read(self, "files/LoggingPolicyState.ps1").lower()
        families = {
            "designated host": ("management_host", "execution_inventory_host"),
            "selected domain/DC": ("get-addomaincontroller", "isreadonly", "-server", "sysvol"),
            "protected state path": ("reparsepoint", "areaccessrulesprotected", "set-acl"),
            "state/marker ownership": ("protected state", "ownership marker", "marked gpo"),
            "pending rejection": ("unresolved pending state", "explicit recovery"),
        }
        for label, tokens in families.items():
            self.assertTrue(all(token in source for token in tokens),
                            f"superficial source contract lost the {label} guard family")

    def test_pending_schema_is_discriminated_and_ownership_is_policy_scoped(self):
        source = ARTIFACTS.read(self, "files/LoggingPolicyState.ps1")
        lowered = source.lower()
        self.assertRegex(source, r"(?i)switch\s*\(\[string\]\s*\$Pending\.operation\)")
        for operation in ("create", "registry_add", "registry_update", "registry_remove",
                          "audit_publish", "audit_delete", "link_add", "link_update", "link_disable"):
            self.assertTrue(f"'{operation}'" in source, f"missing pending discriminator {operation}")
        for helper in ("Assert-LoggingPolicyRegistryIdentifiers", "Assert-LoggingPolicyAuditIdentifiers",
                       "Assert-LoggingPolicyLinkIdentifiers", "Assert-LoggingPolicyStoredLinksInDomain"):
            self.assertTrue(f"function {helper}" in source, f"missing scoped validator {helper}")
        for owned_identifier in ("scenoapplylegacyauditpolicy", "modulenames", "aepolicy", "disableantispyware"):
            self.assertTrue(owned_identifier in lowered, f"missing owned identifier {owned_identifier}")
        self.assertTrue("0cce9242" in lowered and "-69ae-11d9-bed3-505054503030" in lowered, "missing audit GUID prefix/shared-suffix representation")
        for invariant in ("desired_deletion must be true exactly when desired_hash is null", "audit_publish cannot request csv deletion"):
            self.assertTrue(invariant in lowered, f"missing audit intent invariant: {invariant}")

    def test_w3_entrypoint_passes_the_documented_lowercase_configuration(self):
        main = ARTIFACTS.yaml_list(self, "tasks/main.yml")
        policy = ARTIFACTS.yaml_list(self, "tasks/policy.yml")
        include_indexes = [i for i, task in enumerate(main)
                           if task.get("ansible.builtin.include_tasks") == "policy.yml"]
        self.assertEqual(len(include_indexes), 1, "main must include policy.yml exactly once")
        validation = "\n".join(str(task) for task in main[:include_indexes[0]])
        for token in ("inventory_hostname", "management_host", "type_debug"):
            self.assertIn(token, validation, f"entrypoint validation missing {token}")

        powershell = [task["ansible.windows.win_powershell"] for task in policy
                      if "ansible.windows.win_powershell" in task]
        self.assertEqual(len(powershell), 1, "policy must have one win_powershell entrypoint")
        module = powershell[0]
        configuration = module.get("parameters", {}).get("Configuration")
        self.assertIsInstance(configuration, dict)
        self.assertEqual(set(configuration), CONFIGURATION_KEYS)
        self.assertEqual(configuration["execution_inventory_host"], "{{ inventory_hostname }}")
        self.assertIn("audit.csv.j2", str(configuration["desired_audit_csv"]))
        self.assertEqual(module.get("error_action"), "stop")
        self.assertNotIn("path", module, "entrypoint must not remotely stage scripts")
        wrapper = module.get("script", "")
        for token in ("[CmdletBinding(SupportsShouldProcess)]", "LoggingPolicyState.ps1",
                      "Invoke-LoggingPolicy.ps1", "Publish-LoggingAudit.ps1", "lookup(",
                      "$Ansible.Changed = $false", "$Ansible.Result",
                      "Invoke-LoggingPolicy -Configuration $Configuration -PlanOnly $Ansible.CheckMode"):
            self.assertIn(token, wrapper, f"entrypoint wrapper missing {token}")

    def test_w3_public_interfaces_and_result_shapes_are_explicit(self):
        contracts = {
            "files/Invoke-LoggingPolicy.ps1": ("Invoke-LoggingPolicy",
                (("hashtable", "Configuration"), ("bool", "PlanOnly"),
                 ("hashtable", "Progress")),
                ("changed", "planned_changes", "policies")),
            "files/Publish-LoggingAudit.ps1": ("Publish-LoggingAudit",
                (("hashtable", "Context"), ("hashtable", "State"),
                 ("string", "DesiredCsv"), ("bool", "PlanOnly")),
                ("changed", "state")),
        }
        for artifact, (name, parameters, result_keys) in contracts.items():
            block = function_block(self, ARTIFACTS.read(self, artifact), name)
            for kind, parameter in parameters:
                self.assertRegex(block, rf"(?i)\[{kind}\]\s*\${parameter}\b")
            for key in result_keys:
                self.assertRegex(block, rf"(?i)\b{key}\s*=", f"{name} result missing {key}")

    def test_native_mutations_use_explicit_identity_and_forbid_broad_operations(self):
        invoke = ARTIFACTS.read(self, "files/Invoke-LoggingPolicy.ps1")
        logical = re.sub(r"`\r?\n\s*", " ", invoke)
        create = re.findall(r"(?im)^[^#\r\n]*\bNew-GPO\b[^\r\n]*$", logical)
        self.assertTrue(create, "missing native New-GPO call")
        for line in create:
            for parameter in ("Name", "Domain", "Server"):
                self.assertRegex(line, rf"(?i)-{parameter}\b")
        for command in ("Get-GPRegistryValue", "Set-GPRegistryValue", "Remove-GPRegistryValue",
                        "New-GPLink", "Set-GPLink"):
            lines = re.findall(rf"(?im)^[^#\r\n]*\b{command}\b[^\r\n]*$", logical)
            self.assertTrue(lines, f"missing native call {command}")
            for line in lines:
                for parameter in ("Guid", "Domain", "Server"):
                    self.assertRegex(line, rf"(?i)-{parameter}\b",
                                     f"{command} must pass -{parameter} explicitly")
        for line in re.findall(r"(?im)^[^#\r\n]*\bRemove-GPRegistryValue\b[^\r\n]*$", logical):
            self.assertRegex(line, r"(?i)-ValueName\b", "key-wide registry deletion is forbidden")
        for forbidden in ("Remove-GPO", "Import-GPO", "Restore-GPO", "Backup-GPO",
                          "Remove-GPLink", "gpupdate", "auditpol", "PolicyServers",
                          "Set-CertificateAutoEnrollmentPolicy"):
            self.assertNotRegex(invoke, rf"(?im)^(?!\s*#)[^\r\n#]*\b{re.escape(forbidden)}\b")

    def test_write_guards_pending_and_readback_phase_order_remain_visible(self):
        invoke_source = ARTIFACTS.read(self, "files/Invoke-LoggingPolicy.ps1")
        invoke = function_block(self, invoke_source, "Invoke-LoggingPolicy")
        for token in ("$PlanOnly", "ShouldProcess", "try", "finally", ".Dispose()"):
            self.assertIn(token.lower(), invoke.lower(), f"public orchestrator missing {token}")
        for token in ("ShouldProcess", "prior_ownership", "intended_ownership",
                      "Write-LoggingPolicyState", "registry_remove", "audit_delete", "link_disable"):
            self.assertIn(token.lower(), invoke_source.lower(), f"orchestrator missing {token}")
        contexts = [match.start() for match in re.finditer(r"Get-LoggingPolicyContext", invoke, re.I)]
        lock = re.search(r"Enter-LoggingPolicyWriter", invoke, re.I)
        first_write = re.search(r"Reconcile-LoggingPolicyObjects", invoke, re.I)
        self.assertGreaterEqual(len(contexts), 2, "context must be reread under the writer lock")
        self.assertIsNotNone(lock, "public orchestrator must acquire the writer lock")
        self.assertIsNotNone(first_write, "missing first mutation phase")
        self.assertTrue(contexts[0] < lock.start() < contexts[1] < first_write.start())
        assert_order(self, invoke, (
            ("GPO ownership reconciliation", r"Reconcile-LoggingPolicyObjects"),
            ("native registry reconciliation", r"Reconcile-LoggingPolicyRegistry"),
            ("audit publication", r"Publish-LoggingAudit"),
            ("links after verified content", r"Reconcile-LoggingPolicyLinks"),
        ))

        publish_source = ARTIFACTS.read(self, "files/Publish-LoggingAudit.ps1")
        publish = function_block(self, publish_source, "Publish-LoggingAudit")
        for token in ("$PlanOnly", "ShouldProcess"):
            self.assertIn(token.lower(), publish.lower(), f"public publisher missing {token}")
        for token in ("writer", "ownership", "desired_deletion",
                      "audit_delete", "prior_hash", "desired_hash", "$Context.dc",
                      "$Context.gpo_dn", "SearchRequest", "ModifyRequest"):
            self.assertIn(token.lower(), publish_source.lower(), f"publisher missing {token}")
        assert_order(self, publish, (
            ("pending persisted", r"Start-LoggingAuditPending"),
            ("audit payload publication", r"Write-LoggingAuditPayload"),
            ("combined LDAP replacement", r"Set-LoggingAuditLdapState"),
            ("GPT version publication", r"Set-LoggingAuditGptVersion"),
            ("authoritative readback", r"Assert-LoggingAuditReadback"),
            ("pending clear after readback", r"Complete-LoggingAuditPending"),
        ))
        pending = function_block(self, publish_source, "Start-LoggingAuditPending")
        self.assertIn("Write-LoggingPolicyState", pending)

    def test_audit_template_has_exact_header_and_owned_guid_rows(self):
        template = ARTIFACTS.read(self, "templates/audit.csv.j2")
        header = ("Machine Name,Policy Target,Subcategory,Subcategory GUID,"
                  "Inclusion Setting,Exclusion Setting,Setting Value")
        self.assertEqual(template.splitlines()[0], header)
        for token in ("audit_subcategories", "guid", "success", "failure"):
            self.assertIn(token, template)

    def test_audit_payload_is_verified_before_ldap_and_gpt_publication(self):
        source = ARTIFACTS.read(self, "files/Publish-LoggingAudit.ps1")
        publish = function_block(self, source, "Publish-LoggingAudit")
        assert_order(self, publish, (
            ("payload write", r"Write-LoggingAuditPayload"),
            ("payload-only readback", r"Assert-LoggingAuditPayloadReadback"),
            ("LDAP publication", r"Set-LoggingAuditLdapState"),
            ("GPT publication", r"Set-LoggingAuditGptVersion"),
            ("final full readback", r"Assert-LoggingAuditReadback"),
        ))

    def test_unrelated_audit_guids_and_per_user_sids_use_authoritative_sets(self):
        source = ARTIFACTS.read(self, "files/Publish-LoggingAudit.ps1")
        lowered = source.lower()
        for prefix in SUPPORTED_AUDIT_PREFIXES:
            self.assertIn(f"{prefix}-69ae-11d9-bed3-505054503030", lowered,
                          f"missing source-backed MS-GPAC GUID {prefix}")
        sid_block = function_block(self, source, "Get-LoggingAuditCanonicalSid")
        self.assertIn("System.Security.Principal.SecurityIdentifier", sid_block)
        self.assertRegex(sid_block, r"(?i)\.Value\b")

    def test_gate_remediation_contracts_remain_visible(self):
        helper = function_block(
            self, ARTIFACTS.read(self, "files/LoggingPolicyState.ps1"),
            "Assert-LoggingPolicyInteger")
        self.assertRegex(helper, r"(?i)-is\s+\[uint32\]",
                         "state validation must accept the publisher's UInt32 versions")

        invoke_source = ARTIFACTS.read(self, "files/Invoke-LoggingPolicy.ps1")
        invoke_public = function_block(self, invoke_source, "Invoke-LoggingPolicy")
        self.assertRegex(invoke_public, r"(?i)\[hashtable\]\s*\$Progress\b")
        logical = re.sub(r"`\r?\n\s*", " ", invoke_source)
        create = re.findall(r"(?im)^[^#\r\n]*\bNew-GPO\b[^\r\n]*$", logical)
        self.assertTrue(create and all(re.search(r"(?i)-Comment\b", line) for line in create),
                        "the ownership marker must be supplied atomically to New-GPO")
        self.assertNotRegex(invoke_source, r"(?im)^(?!\s*#)[^\r\n#]*\bSet-GPO\b")

        registry = function_block(self, invoke_source, "Reconcile-LoggingPolicyRegistry")
        assert_order(self, registry, (
            ("read existing value", r"Get-LoggingPolicyRegistryValue"),
            ("reject unowned collision", r"outside committed ownership"),
            ("plan mutation", r"Add-LoggingPolicyPlan"),
            ("check-mode guard", r"\$PlanOnly"),
        ))

        module = ARTIFACTS.yaml_list(self, "tasks/policy.yml")[0][
            "ansible.windows.win_powershell"]
        self.assertEqual(
            module.get("depth"), 3,
            "result -> partial_failure -> arrays -> operation records requires depth 3")
        wrapper = module["script"]
        for token in ("New-LoggingPolicyProgress", "Get-LoggingPolicyFailureResult",
                      "$Ansible.Failed = $true", "catch", "throw"):
            self.assertIn(token, wrapper, f"failure wrapper missing {token}")
        for token in ("affected_policy", "phase", "state_path", "completed", "uncertain"):
            self.assertIn(token, invoke_source,
                          f"invocation-local failure progress missing {token}")

if __name__ == "__main__":
    unittest.main()
