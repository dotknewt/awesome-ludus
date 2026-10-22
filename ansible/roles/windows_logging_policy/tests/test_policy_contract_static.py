"""Explicit-path W2 checks; PowerShell patterns are superficial and prove no
native guard behavior, ordering, locking, ACL, atomicity, or AD/SYSVOL semantics."""
from pathlib import Path
import re
import sys
import unittest
import yaml

REQUIRED = {"defaults/main.yml", "meta/main.yml", "LICENSE", "README.md",
            "files/LoggingPolicyState.ps1"}

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
        case.assertTrue(path.is_file(), f"Missing required W2 implementation artifact: {name} ({path})")
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

if __name__ == "__main__":
    unittest.main()
