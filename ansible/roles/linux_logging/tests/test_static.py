"""Static contract tests for the native auditd/Laurel role; no lifecycle fakes."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import re
import unittest

import yaml
from jinja2 import Environment


ROLE = Path(__file__).resolve().parents[1]
CONSTRUCTING_DEFENSE_REVISION = "0cefe62755eebba7b226e611ece75160706e22f6"
LAUREL_SHA256 = "ee7704e87c831bbfcac8cf8741e92eb56b49b3c6d64629d4730c98d97568ec53"

# Minimal unit directives transcribed from Debian 13 audit package sources:
# auditd.service.in and audit-rules.service.in at audit 1:4.0.2-2+deb13u1.
# https://sources.debian.org/data/main/a/audit/1%3A4.0.2-2%2Bdeb13u1/init.d/auditd.service.in
# https://sources.debian.org/data/main/a/audit/1%3A4.0.2-2%2Bdeb13u1/init.d/audit-rules.service.in
_DEBIAN13_AUDITD_UNIT = """# /lib/systemd/system/auditd.service
[Unit]
Requires=audit-rules.service
After=audit-rules.service
[Service]
Type=forking
ExecStart=/sbin/auditd
"""
_DEBIAN13_RULES_UNIT = """# /lib/systemd/system/audit-rules.service
[Unit]
Description=Audit rules
[Service]
Type=oneshot
ExecStart=/usr/sbin/augenrules --load
"""
_LEGACY_AUDITD_UNIT = """# legacy auditd arrangement
[Service]
ExecStart=/sbin/auditd
ExecStartPost=-/sbin/augenrules --load
"""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _yaml(path: Path):
    text = _read(path)
    return yaml.safe_load(text) if text else None


def _task_list(node):
    """Yield task mappings in play order, recursively through blocks."""
    if isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                yield item
                for key in ("block", "rescue", "always"):
                    yield from _task_list(item.get(key, []))


def _expanded_tasks(path: Path, seen=None):
    """Expand literal import_tasks and nested blocks starting from main.yml."""
    seen = set() if seen is None else seen
    resolved = path.resolve()
    if resolved in seen:
        return
    seen.add(resolved)
    node = _yaml(path)
    if not isinstance(node, list):
        return

    def expand(items):
        for task in items if isinstance(items, list) else []:
            if not isinstance(task, dict):
                continue
            imported = task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
            if isinstance(imported, str) and "{{" not in imported:
                yield from _expanded_tasks(path.parent / imported, seen)
                continue
            yield task
            for key in ("block", "rescue", "always"):
                yield from expand(task.get(key, []))

    yield from expand(node)


def _module(task, short_name):
    """Find an Ansible module mapping while accepting FQCN and short names."""
    for key, value in task.items():
        if key.rsplit(".", 1)[-1] == short_name:
            return value if isinstance(value, dict) else {}
    return None


def _production_files():
    return [
        path
        for path in ROLE.rglob("*")
        if path.is_file() and "tests" not in path.relative_to(ROLE).parts
        and path.suffix in {".yml", ".yaml", ".j2", ".py", ".rules", ".toml", ".conf"}
    ]


class NativeLinuxLoggingStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _yaml(ROLE / "defaults/main.yml") or {}
        cls.meta = _yaml(ROLE / "meta/main.yml") or {}
        cls.task_files = sorted((ROLE / "tasks").glob("**/*.yml"))
        cls.tasks = list(_expanded_tasks(ROLE / "tasks/main.yml"))
        cls.task_names = [str(task.get("name", "")) for task in cls.tasks]
        cls.production = "\n".join(_read(path) for path in _production_files())
        cls.readme = re.sub(r"\s+", " ", _read(ROLE / "README.md"))

    def _required_task(self, name):
        matches = [task for task in self.tasks if task.get("name") == name]
        self.assertTrue(matches, f"missing production task contract: {name}")
        return matches[0] if matches else {}

    def test_role_skeleton_and_independent_metadata_are_present(self):
        for path in ("defaults/main.yml", "meta/main.yml", "tasks/main.yml", "README.md"):
            with self.subTest(path=path):
                self.assertTrue((ROLE / path).is_file(), f"missing native role artifact: {path}")
        galaxy = self.meta.get("galaxy_info", {})
        self.assertEqual(galaxy.get("role_name"), "linux_logging")
        self.assertEqual(galaxy.get("author"), "dotknewt")
        self.assertEqual(galaxy.get("min_ansible_version"), "2.16")
        self.assertEqual(self.meta.get("dependencies"), [], "the role must not depend on its collector sibling")
        platforms = galaxy.get("platforms", [])
        self.assertTrue(any(p.get("name") == "Debian" and "trixie" in p.get("versions", []) for p in platforms))
        self.assertTrue(any(p.get("name") == "Ubuntu" and any(v in p.get("versions", []) for v in ("24.04", "noble")) for p in platforms))
        self.assertTrue(any(p.get("name") == "Ubuntu" and any(v in p.get("versions", []) for v in ("26.04", "resolute")) for p in platforms))

    def test_public_defaults_define_reader_and_laurel_identity(self):
        self.assertEqual(self.defaults.get("ludus_linux_logging_read_users"), ["debian"])
        self.assertEqual(self.defaults.get("ludus_linux_logging_laurel_log_dir"), "/var/log/laurel")
        self.assertEqual(self.defaults.get("ludus_linux_logging_laurel_user"), "_laurel")
        for key in self.defaults:
            self.assertTrue(key.startswith("ludus_linux_logging_"), f"un-namespaced default {key}")

    def test_persisted_generated_file_markers_keep_legacy_protocol_identity(self):
        marker = "Managed by ludus_linux_logging"
        helper = _read(ROLE / "filter_plugins/ludus_linux_logging.py")
        template = _read(ROLE / "templates/laurel.conf.j2")
        tasks = _read(ROLE / "tasks/main.yml")
        self.assertIn(marker, helper)
        self.assertIn(marker, template)
        self.assertIn(marker, tasks)

    def test_pinned_https_artifacts_and_transport_hash_provenance_are_declared(self):
        artifact_paths = (
            f"{CONSTRUCTING_DEFENSE_REVISION}/audit.rules",
            f"{CONSTRUCTING_DEFENSE_REVISION}/config.toml",
            "laurel-v0.6.3-x86_64-musl.tar.gz",
        )
        for artifact in artifact_paths:
            self.assertIn(artifact, self.production + self.readme, f"artifact must be fetched from pinned HTTPS source: {artifact}")
        self.assertIn(LAUREL_SHA256, self.production + self.readme)
        self.assertRegex(self.production, r"https://")
        self.assertRegex(self.production, r"checksum\s*:\s*sha256:")
        for forbidden in ("no-check-certificate", "curl -k", "wget --no-check-certificate"):
            self.assertNotIn(forbidden, self.production.lower())
        text = (self.production + self.readme).lower()
        self.assertIn("transport", text, "document computed SHA-256 provenance and that it is not publisher authenticity")
        self.assertIn("constructingdefense", text, "retain upstream attribution without vendoring unlicensed files")
        self.assertRegex(text, r"(no|not) (verified )?redistribution license|license.{0,40}(unverified|not verified|not established)")

    def test_laurel_binary_install_and_plugin_contract_are_explicit(self):
        text = self.production + self.readme
        for required in ("0.6.3", "/usr/local/sbin/laurel", "/etc/laurel/config.toml", "--config", "active = yes", "direction = out", "type = always", "format = string"):
            self.assertIn(required, text, f"missing Laurel contract: {required}")
        self.assertIn(LAUREL_SHA256, text)
        self.assertNotRegex(self.production.lower(), r"(?:bash|sh)\s+.*(?:https?://|laurel.*\.sh)")
        self.assertNotRegex(self.production, r"cap_(?:dac_read_search|sys_ptrace)|CAP_DAC_READ_SEARCH|CAP_SYS_PTRACE")
        self.assertRegex(self.readme.lower(), r"(enrichment|capabilit).{0,120}(retained|cap_dac_read_search|sys_ptrace)")

    def test_upstream_policy_is_not_vendored_and_role_owns_separate_rules_fragment(self):
        paths = _production_files()
        self.assertFalse(any(path.name == "audit.rules" for path in paths), "do not redistribute the unlicensed upstream rules file")
        self.assertFalse(any(path.name == "config.toml" for path in paths), "do not redistribute the unlicensed upstream config")
        self.assertRegex(self.production + self.readme, r"/etc/audit/rules\.d/60-ludus-linux-logging\.rules")
        self.assertNotRegex(self.production, r"(?im)^\s*(?:-D| -D)(?:\s|$)")
        self.assertIn("Protect pre-existing unmanaged augenrules output", self.task_names)
        self.assertRegex(self.readme, r"(?i)(preserv|never delete|unrelated).{0,180}audit\.rules|audit\.rules.{0,180}(preserv|never delete|unrelated)")

    def test_input_and_platform_guards_are_before_mutating_tasks(self):
        self.assertTrue(self.tasks, "production role task YAML is missing or empty")
        mutating_modules = {"apt", "package", "get_url", "copy", "template", "file", "unarchive", "user"}
        first_mutation = next((i for i, task in enumerate(self.tasks) if any(_module(task, module) is not None for module in mutating_modules)), None)
        self.assertIsNotNone(first_mutation, "role needs explicit native package/configuration tasks")
        assertions = [i for i, task in enumerate(self.tasks) if _module(task, "assert") is not None]
        self.assertTrue(assertions, "fail-closed platform/input/user guards are missing")
        self.assertLess(min(assertions), first_mutation, "platform and safe-input checks must precede mutation")
        text = self.production
        for contract in ("ansible_distribution", "ansible_distribution_version", "ansible_architecture", "ansible_service_mgr", "getent", "ludus_linux_logging_read_users"):
            self.assertIn(contract, text, f"missing pre-mutation guard for {contract}")
        self.assertRegex(self.readme, r"(?i)(does not|never|must not).{0,80}(create|change).{0,80}(template|login|account)")
        user_tasks = [(task, _module(task, "user")) for task in self.tasks if _module(task, "user") is not None]
        self.assertTrue(user_tasks, "role must create the dedicated Laurel service account")
        for task, args in user_tasks:
            self.assertIn(args.get("name"), ("{{ ludus_linux_logging_laurel_user }}", "_laurel"),
                          f"user task may manage only the role's Laurel identity: {task.get('name')}")
            self.assertIs(args.get("system"), True, "Laurel identity must be a system account")

    def test_rules_fragment_transformation_preserves_existing_audit_state(self):
        source_text = self.production
        self.assertRegex(source_text, r"(?i)(auditctl\s+-s|immutable|enabled\s*==\s*2)")
        self.assertRegex(source_text, r"(?i)(immutable|enabled\s*==\s*2).{0,220}(fail|assert|operator|cannot|refus)")
        self.assertNotRegex(source_text, r"(?i)auditctl\s+[^\n]{0,100}(?:--check|-c\b)")
        self.assertRegex(source_text, r"(?i)augenrules\s+--check")
        self.assertRegex(source_text, r"(?i)(merged|runtime-only|runtime rules).{0,180}(reset|wipe|global|operator)|(?:reset|wipe|global).{0,180}(merged|runtime-only|runtime rules)")
        self.assertRegex(source_text, r"(?i)(kubectl|path|dir).{0,180}(exists|stat|omit|skip)|(?:exists|stat|omit|skip).{0,180}(kubectl|path|dir)")
        self.assertIn("/usr/local/bin/kubectl", source_text)
        protected = ("/etc/audit/audit.rules", "/etc/audit/rules.d")
        for task in self.tasks:
            file_args = _module(task, "file") or {}
            if file_args.get("state") == "absent":
                target = str(file_args.get("path", file_args.get("dest", "")))
                self.assertFalse(any(target == item or target.startswith(item + "/") for item in protected),
                                 f"must not delete existing audit policy: {task.get('name')}")
            for module_name in ("command", "shell"):
                args = _module(task, module_name) or {}
                command = str(args.get("cmd", args.get("argv", "")))
                if re.search(r"\brm\b", command):
                    self.assertFalse(any(item in command for item in protected),
                                     f"must not remove protected audit policy: {task.get('name')}")

    def test_laurel_reader_acl_and_config_defaults_preserve_policy(self):
        text = self.production + self.readme
        for required in ('"/var/log/laurel"', '"_laurel"', '"debian"', "5000000", "generations", "read-users", "ACL", "rotation"):
            self.assertIn(required, text, f"missing Laurel config/permissions contract: {required}")
        self.assertRegex(text, r"(?i)(per-file|each file|every file).{0,120}ACL|ACL.{0,120}(per-file|each file|every file)")
        self.assertRegex(text, r"(?i)(read-users|reader).{0,160}(exist|account)|(?:exist|account).{0,160}(read-users|reader)")
        self.assertRegex(self.readme.lower(), r"default acl.{0,100}(not|does not|insufficient)|(?:not|does not|insufficient).{0,100}default acl")
        self.assertRegex(text, r"(?i)(enrichment|filter-action|execve|ld_preload)")

    def test_handlers_and_documented_restart_constraints_are_static_contracts(self):
        main = _yaml(ROLE / "tasks/main.yml")
        self.assertIsInstance(main, list, "tasks/main.yml must be valid role task YAML")
        handlers = _yaml(ROLE / "handlers/main.yml")
        self.assertIsInstance(handlers, list, "idempotent auditd/Laurel handlers are missing")
        handler_text = _read(ROLE / "handlers/main.yml")
        self.assertRegex(handler_text, r"(?i)(auditd|laurel)")
        self.assertNotRegex(handler_text, r"(?i)systemctl\s+restart\s+auditd")
        self.assertRegex(self.readme.lower(), r"(?i)(debian|ubuntu).{0,100}(restart|reconfigure|reload)|(restart|reconfigure|reload).{0,100}(debian|ubuntu)")
        self.assertIn("ansible-core >= 2.16", self.readme)
        self.assertRegex(self.readme.lower(), r"(?i)(unverified|not verified).{0,120}(compatib|native|deployment)|(compatib|native|deployment).{0,120}(unverified|not verified)")

    def test_fresh_auditd_prerequisite_is_bounded_and_state_is_checked_before_policy(self):
        names = [task.get("name") for task in self.tasks]
        apt_task = next(task for task in self.tasks if _module(task, "apt") is not None)
        self.assertEqual(_module(apt_task, "apt").get("name"), "auditd")
        self.assertEqual(_module(apt_task, "apt").get("policy_rc_d"), 101)
        preinstall = names.index("Read existing kernel audit status before package work when auditctl is present")
        preinstall_immutable = names.index("Refuse an already immutable kernel audit state before package work")
        prerequisite = names.index("Ensure auditd prerequisite is installed without allowing package startup")
        immutable = names.index("Refuse immutable audit state before role policy or service changes")
        first_policy_write = names.index("Install separate managed Linux audit rules fragment")
        self.assertLess(preinstall, prerequisite)
        self.assertLess(preinstall_immutable, prerequisite)
        self.assertLess(prerequisite, immutable)
        self.assertLess(immutable, first_policy_write)
        self.assertTrue(any(_module(task, "command") and _module(task, "command").get("argv") == ["/usr/sbin/auditctl", "-l"] for task in self.tasks))
        self.assertIn("Refuse unsafe first start when inactive auditd has runtime-only rules", names)
        self.assertIn("Protect pre-existing unmanaged augenrules output", names)
        self.assertIn("Generate persistent merged rules from rules.d without loading them", names)
        generation = next(task for task in self.tasks if task.get("name") == "Generate persistent merged rules from rules.d without loading them")
        self.assertEqual(_module(generation, "command").get("argv"), ["/usr/sbin/augenrules"])
        service = next(task for task in self.tasks if task.get("name") == "Enable and start auditd after persistent rules and Laurel plugin are ready")
        self.assertIs(_module(service, "service").get("enabled"), True)
        self.assertEqual(_module(service, "service").get("state"), "started")
        self.assertLess(names.index("Install Laurel audit plugin configuration"), names.index(service["name"]))
        for task in self.tasks:
            if task.get("name") == "Refuse unsafe first start when inactive auditd has runtime-only rules":
                self.assertIsNotNone(_module(task, "assert"))
        for handler in _yaml(ROLE / "handlers/main.yml"):
            self.assertIs(handler.get("become"), True, f"handler must run as root: {handler.get('name')}")
            self.assertNotEqual(_module(handler, "service").get("state") if _module(handler, "service") else None, "restarted")
        rule_handler = next(handler for handler in _yaml(ROLE / "handlers/main.yml") if handler.get("name") == "Load only the managed audit rules fragment")
        self.assertEqual(_module(rule_handler, "command").get("argv"), ["/usr/sbin/auditctl", "-R", "/etc/audit/rules.d/60-ludus-linux-logging.rules"])

    def test_active_policy_changes_are_rejected_and_log_identity_is_safe(self):
        names = [task.get("name") for task in self.tasks]
        compare = names.index("Refuse active rule-policy edits that would leave stale runtime rules")
        write = names.index("Install separate managed Linux audit rules fragment")
        self.assertLess(compare, write)
        account_guard = next(task for task in self.tasks if task.get("name") == "Reject an existing Laurel identity that this role must not rewrite")
        conditions = " ".join(str(item) for item in _module(account_guard, "assert").get("that", []))
        self.assertIn("int > 0", conditions)
        platform_guard = next(task for task in self.tasks if task.get("name") == "Validate platform, public inputs, and path ownership boundaries before mutation")
        platform_conditions = " ".join(str(item) for item in _module(platform_guard, "assert").get("that", []))
        self.assertIn("ludus_linux_logging_laurel_log_dir", platform_conditions)
        self.assertIn("/var/log/", platform_conditions)
        self.assertIn("/var/log/audit", platform_conditions)
        type_guard = next(task for task in self.tasks if task.get("name") == "Refuse symlinked role-owned targets and unmanaged existing files")
        type_conditions = " ".join(str(item) for item in _module(type_guard, "assert").get("that", []))
        self.assertIn("isdir", type_conditions)
        self.assertIn("isreg", type_conditions)
        self.assertTrue((ROLE / "LICENSE").is_file(), "the authored role must retain its GPL-3.0-or-later license notice")
        license_text = _read(ROLE / "LICENSE")
        self.assertIn("GNU GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("Version 3", license_text)
        self.assertRegex(self.readme, r"(?i)existing.*auditctl|auditctl.*existing")
        self.assertNotRegex(self.readme, r"(?i)install.*auditd.*first.*rerun")

    def test_reload_uses_auditctl_signal_and_records_only_verified_apply(self):
        handlers = _yaml(ROLE / "handlers/main.yml")
        reload_handler = next(handler for handler in handlers if handler.get("name") == "Reload auditd configuration without restarting the service")
        self.assertEqual(_module(reload_handler, "command").get("argv"), ["/usr/sbin/auditctl", "--signal", "reload"])
        self.assertIs(reload_handler.get("become"), True)
        names = self.task_names
        pending = names.index("Write pending apply marker before managed policy/configuration changes")
        first_config_write = names.index("Preserve upstream Laurel defaults with explicit role identity and paths")
        record = names.index("Record content digests only after rules and plugin readiness gates pass")
        clear = names.index("Clear pending marker only after successful apply gates and digest write")
        self.assertLess(pending, first_config_write)
        self.assertLess(names.index("Require kernel auditing to be enabled without overriding state"), record)
        self.assertLess(names.index("Confirm applied digest inputs match the exact managed disk content"), record)
        self.assertLess(record, clear)
        self.assertIn("pgrep", self.production)

    def test_pending_marker_and_digest_updates_are_guarded_by_real_apply_need(self):
        decision = next(
            task for task in self.tasks
            if task.get("name") == "Decide whether a managed apply is actually required"
        )
        expression = str((_module(decision, "set_fact") or {}).get("ludus_linux_logging_needs_apply", ""))
        for required in (
            "initial_service_state.stdout != 'active'",
            "desired_digests.rules", "desired_digests.config", "desired_digests.plugin",
            "prior_managed_file_digests.rules", "prior_managed_file_digests.config",
            "prior_managed_file_digests.plugin",
        ):
            self.assertIn(required, expression)

        for name in (
            "Write pending apply marker before managed policy/configuration changes",
            "Record content digests only after rules and plugin readiness gates pass",
            "Clear pending marker only after successful apply gates and digest write",
        ):
            task = next(task for task in self.tasks if task.get("name") == name)
            self.assertIn("ludus_linux_logging_needs_apply", str(task.get("when")), name)

    def test_prior_config_and_plugin_digest_expressions_parse_as_real_jinja(self):
        task = next(
            task for task in self.tasks
            if task.get("name") == "Compute exact prior managed-file digests"
        )
        digest_values = (_module(task, "set_fact") or {}).get(
            "ludus_linux_logging_prior_managed_file_digests", {}
        )
        self.assertEqual(set(digest_values), {"rules", "config", "plugin"})
        environment = Environment()
        for key in ("config", "plugin"):
            with self.subTest(digest=key):
                parsed = environment.parse(digest_values[key])
                self.assertIsNotNone(parsed)

    def test_auditd_loader_supports_debian_rules_service_and_legacy_post_hook(self):
        helper_path = ROLE / "filter_plugins/ludus_linux_logging.py"
        spec = importlib.util.spec_from_file_location("ludus_linux_logging_filter", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        inspect_loader = getattr(helper, "auditd_loader_contract", None)
        if not callable(inspect_loader):
            self.fail("missing pure effective-unit loader parser auditd_loader_contract")
        debian_contract = inspect_loader(_DEBIAN13_AUDITD_UNIT, _DEBIAN13_RULES_UNIT)
        self.assertEqual(debian_contract["unit"], "audit-rules.service")
        self.assertEqual(debian_contract["directive"], "ExecStart")
        self.assertIn(debian_contract["argv"], (
            ["/usr/sbin/augenrules", "--load"],
            ["/sbin/augenrules", "--load"],
        ))

        legacy_contract = inspect_loader(_LEGACY_AUDITD_UNIT, "")
        self.assertEqual(legacy_contract["unit"], "auditd.service")
        self.assertEqual(legacy_contract["directive"], "ExecStartPost")
        self.assertIn(legacy_contract["argv"], (
            ["/usr/sbin/augenrules", "--load"],
            ["/sbin/augenrules", "--load"],
        ))

        # systemctl cat includes drop-ins. A reset/override must not be ignored.
        overridden_rules = _DEBIAN13_RULES_UNIT + """# /etc/systemd/system/audit-rules.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/bin/true
"""
        self.assertIsNone(inspect_loader(_DEBIAN13_AUDITD_UNIT, overridden_rules))
        missing_ordering = _DEBIAN13_AUDITD_UNIT.replace("After=audit-rules.service\n", "")
        self.assertIsNone(inspect_loader(missing_ordering, _DEBIAN13_RULES_UNIT))

    def test_auditd_loader_result_helpers_check_recorded_execution_status(self):
        helper_path = ROLE / "filter_plugins/ludus_linux_logging.py"
        spec = importlib.util.spec_from_file_location("ludus_linux_logging_filter", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        rules_result_succeeded = getattr(helper, "auditd_rules_loader_succeeded", None)
        if not callable(rules_result_succeeded):
            self.fail("missing oneshot execution-result checker auditd_rules_loader_succeeded")
        self.assertTrue(rules_result_succeeded(
            "Result=success\nExecMainCode=1\nExecMainStatus=0\n"
        ))
        self.assertFalse(rules_result_succeeded(
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        ))
        self.assertFalse(rules_result_succeeded(
            "Result=exit-code\nExecMainCode=1\nExecMainStatus=1\n"
        ))
        self.assertFalse(rules_result_succeeded(
            "Result=signal\nExecMainCode=2\nExecMainStatus=9\n"
        ))
        self.assertTrue(helper.auditd_startpost_succeeded(
            "ExecStartPost={ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; "
            "ignore_errors=yes ; start_time=[1] ; stop_time=[2] ; pid=42 ; code=exited ; status=0 }"
        ))
        self.assertFalse(helper.auditd_startpost_succeeded(
            "ExecStartPost={ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; code=exited ; status=1 }"
        ))
        self.assertFalse(helper.auditd_startpost_succeeded(
            "ExecStartPost={ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; code=exited ; status=0 }\n"
            "ExecStartPost={ path=/usr/bin/true ; argv[]=/usr/bin/true ; code=exited ; status=0 }"
        ))
        self.assertFalse(helper.auditd_startpost_succeeded(
            "ExecStartPost={ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; code=exited ; status=0 } ; "
            "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; code=exited ; status=0 }"
        ))
        self.assertFalse(helper.auditd_startpost_succeeded(
            "ExecStartPost={ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; code=exited ; status=0 }"
            .replace("code=exited", "code=0")
        ))

    def test_auditd_unit_and_startup_checks_are_only_for_fresh_start(self):
        cat_tasks = []
        show_tasks = []
        for task in self.tasks:
            args = _module(task, "command") or {}
            argv = args.get("argv", [])
            text = str(argv) + str(task.get("loop", ""))
            if "systemctl" in text and "cat" in text:
                cat_tasks.append((task, text))
            if "systemctl" in text and "show" in text:
                show_tasks.append(text)
        self.assertTrue(any("auditd.service" in item and "audit-rules.service" in item for _, item in cat_tasks),
                        "inspect both effective units with systemctl cat so drop-ins are included")
        inactive_condition = "initial_service_state.stdout != 'active'"
        shape_gate = self._required_task("Validate effective auditd rule-loader configuration")
        self.assertIn(inactive_condition, str(shape_gate.get("when")),
                      "startup loader-shape gate must be skipped for an already-active daemon")
        for task, text in cat_tasks:
            if "auditd.service" in text or "audit-rules.service" in text:
                self.assertIn(inactive_condition, str(task.get("when")),
                              "effective startup-unit cat checks must be skipped for an already-active daemon")
        self.assertTrue(any("audit-rules.service" in item and "ExecMainStatus" in item for item in show_tasks),
                        "check oneshot loader execution status, not its post-exit active state")
        legacy_show = next((item for item in show_tasks
                            if "auditd.service" in item and "ExecStartPost" in item), "")
        self.assertTrue(legacy_show,
                        "retain the legacy post-hook result check for that recognized unit layout")
        self.assertNotIn("--value", legacy_show,
                         "named property output is required by the legacy result parser")
        separate_gate = self._required_task("Require successful separate merged-rules loader execution")
        legacy_gate = self._required_task("Require successful legacy augenrules startup hook")
        self.assertIn(inactive_condition, str(separate_gate.get("when")))
        self.assertIn("audit-rules.service", str(separate_gate.get("when")))
        self.assertIn(inactive_condition, str(legacy_gate.get("when")))
        self.assertIn("auditd.service", str(legacy_gate.get("when")))

    def test_audit_rule_application_is_content_gated_not_metadata_gated(self):
        decision = self._required_task("Decide whether managed audit rule content changed")
        decision_expression = str((_module(decision, "set_fact") or {}).get(
            "ludus_linux_logging_rules_content_changed", ""
        ))
        self.assertIn("ludus_linux_logging_prior_rules", decision_expression)
        self.assertIn("ludus_linux_logging_managed_rules", decision_expression)

        rule_copy = self._required_task("Install separate managed Linux audit rules fragment")
        self.assertNotIn("Load only the managed audit rules fragment", str(rule_copy.get("notify")),
                         "normal copy metadata changes must not trigger auditctl -R")
        self.assertIsNone(rule_copy.get("changed_when"),
                          "preserve copy's real metadata/content change reporting")

        load_request = self._required_task("Request scoped rule load for changed rule content")
        self.assertIsNotNone(_module(load_request, "debug"), "content-only trigger must not mutate host state")
        self.assertIn("ludus_linux_logging_rules_content_changed", str(load_request.get("changed_when")))
        self.assertIn("Load only the managed audit rules fragment", str(load_request.get("notify")))

        generation = self._required_task("Generate persistent merged rules from rules.d without loading them")
        self.assertIn("ludus_linux_logging_rules_content_changed", str(generation.get("when")))
        self.assertNotIn("ludus_linux_logging_rules_file.changed", str(generation.get("when")))

        handlers = _yaml(ROLE / "handlers/main.yml")
        rule_handler = next(handler for handler in handlers
                            if handler.get("name") == "Load only the managed audit rules fragment")
        self.assertIn("initial_service_state.stdout == 'active'", str(rule_handler.get("when")))
        rules_helper = _read(ROLE / "filter_plugins/ludus_linux_logging.py")
        self.assertIn('tokens[0] in {"-D", "-e", "-i"}', rules_helper)
        commands = [str(_module(task, "command") or {}) for task in self.tasks]
        self.assertFalse(any("auditctl" in command and "-D" in command for command in commands))
        self.assertFalse(any("auditctl" in command and "-e 1" in command for command in commands))

    def test_unapplied_laurel_digests_notify_reconfigure_even_when_copy_is_unchanged(self):
        decision = self._required_task("Decide whether Laurel configuration requires reconfiguration")
        expression = str((_module(decision, "set_fact") or {}).get(
            "ludus_linux_logging_config_reload_required", ""
        ))
        for key in ("config", "plugin"):
            self.assertIn(f"ludus_linux_logging_desired_digests.{key}", expression)
        self.assertIn("ludus_linux_logging_prior_applied_text", expression)

        request = self._required_task("Request auditd reconfiguration for unapplied Laurel digests")
        self.assertIsNotNone(_module(request, "debug"), "digest-only trigger must not mutate host state")
        self.assertIn("ludus_linux_logging_config_reload_required", str(request.get("changed_when")))
        self.assertIn("Reload auditd configuration without restarting the service", str(request.get("notify")))
        reload_handler = next(
            handler for handler in _yaml(ROLE / "handlers/main.yml")
            if handler.get("name") == "Reload auditd configuration without restarting the service"
        )
        self.assertIn("initial_service_state.stdout == 'active'", str(reload_handler.get("when")))

    def test_upstream_rule_omissions_are_narrow_and_explicit(self):
        helper = _read(ROLE / "filter_plugins/ludus_linux_logging.py")
        self.assertIn('tokens[0] in {"-D", "-e", "-i"}', helper)
        self.assertIn("unresolvable named {database} operand {operand}", helper)
        self.assertIn("SELinux absent for predicate {predicate}", helper)
        self.assertIn("omitted exact duplicate rule", helper)
        self.assertIn("unexpected getent status", helper)
        self.assertIn("Preflight environment-dependent named audit uid and gid operands", self.task_names)
        self.assertIn("Inspect SELinux enforcement interface before transforming rules", self.task_names)
        self.assertIn("Refuse active auditd with auditing disabled before role policy mutation", self.task_names)

    def test_any_local_python_helper_is_parseable_and_inspectable(self):
        helpers = [path for path in ROLE.rglob("*.py") if "tests" not in path.relative_to(ROLE).parts]
        for path in helpers:
            with self.subTest(path=path.relative_to(ROLE)):
                try:
                    tree = ast.parse(_read(path), filename=str(path))
                except SyntaxError as exc:
                    self.fail(f"invalid transformation helper syntax in {path}: {exc}")
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported = {alias.name.split(".")[0] for alias in node.names}
                        self.assertFalse(imported & {"subprocess", "urllib", "requests"},
                                         f"helper must not execute commands or fetch artifacts: {path}")
                    if isinstance(node, ast.ImportFrom):
                        imported = (node.module or "").split(".")[0]
                        self.assertNotIn(imported, {"subprocess", "urllib", "requests"},
                                         f"helper must not execute commands or fetch artifacts: {path}")
                    self.assertFalse(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"},
                                     f"helper must remain inspectable: {path}")


if __name__ == "__main__":
    unittest.main()
