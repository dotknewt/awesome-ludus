"""Static contracts over role YAML/Jinja; no host behavior is simulated."""

from pathlib import Path
import importlib.util
import re
import unittest

from jinja2.nativetypes import NativeEnvironment
import yaml


ROLE = Path(__file__).resolve().parents[1]


def _flatten(tasks):
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            yield from _flatten(task.get(section, []))


def _load_yaml(path, default):
    if not path.exists():
        return default
    return yaml.safe_load(path.read_text()) or default


def _task_sequence(role):
    """Expand literal import_tasks in order; do not execute role code."""
    tasks_dir = role / "tasks"

    def expand(tasks, origin):
        for task in tasks:
            yield task
            for section in ("block", "rescue", "always"):
                yield from expand(task.get(section, []), origin)
            imported = task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
            if imported is not None:
                if not isinstance(imported, str) or "{{" in imported:
                    continue
                path = (origin.parent / imported).resolve()
                if not path.exists():
                    continue
                yield from expand(_load_yaml(path, []), path)

    entry = tasks_dir / "main.yml"
    if not entry.exists():
        return []
    return list(expand(_load_yaml(entry, []), entry))


def _linux_task_sequence(role):
    """Expand only the Linux-guarded branch, preserving inherited guards/order."""
    entry = role / "tasks/main.yml"

    def walk(tasks, origin, guards=()):
        for task in tasks or []:
            own = task.get("when", [])
            own = [own] if isinstance(own, str) else own
            effective = (*guards, *own)
            if any("ansible_system == 'win32nt'" in str(guard).lower() for guard in effective):
                continue
            if not any("ansible_system == 'linux'" in str(guard).lower() for guard in effective):
                if not guards:
                    for section in ("block", "rescue", "always"):
                        yield from walk(task.get(section, []), origin, effective)
                continue
            yield task
            for section in ("block", "rescue", "always"):
                yield from walk(task.get(section, []), origin, effective)
            imported = task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
            if isinstance(imported, str) and "{{" not in imported:
                path = (origin.parent / imported).resolve()
                if path.is_file() and "windows" not in path.parts:
                    yield from walk(_load_yaml(path, []), path, effective)

    return list(walk(_load_yaml(entry, []), entry)) if entry.is_file() else []


def _assertion_expressions(task):
    for module in ("ansible.builtin.assert", "assert"):
        if module in task:
            that = task[module].get("that", [])
            return [str(value) for value in (that if isinstance(that, list) else [that])]
    return []


def _module(task, name):
    return task.get("ansible.builtin." + name, task.get(name))


class SplunkCollectorStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _load_yaml(ROLE / "defaults/main.yml", {})
        cls.tasks = _load_yaml(ROLE / "tasks/main.yml", [])
        cls.meta = _load_yaml(ROLE / "meta/main.yml", {})
        cls.syntax = _load_yaml(ROLE / "tests/syntax.yml", [])
        cls.ordered_tasks = _task_sequence(ROLE)
        cls.linux_tasks = _linux_task_sequence(ROLE)
        # Also inspect all task/handler files, including conditionally included tasks.
        cls.flat_tasks = [task for folder in ("tasks", "handlers") if (ROLE / folder).exists()
                          for path in sorted((ROLE / folder).glob("**/*.y*ml"))
                          for task in _flatten(_load_yaml(path, []))]
        cls.source = "\n".join(
            path.read_text()
            for folder in ("tasks", "templates", "handlers", "filter_plugins")
            if (ROLE / folder).exists()
            for path in (ROLE / folder).rglob("*")
            if path.is_file() and path.suffix in {".yml", ".yaml", ".j2", ".py"}
        )

    def test_defaults_pin_verified_artifact_and_safe_lab_inputs(self):
        prefix = "splunk_forwarder_"
        package_url = self.defaults.get(prefix + "package_url", "")
        self.assertIn("splunk_version ~ '/linux/splunkforwarder-' ~ splunk_version", package_url)
        self.assertIn("splunk_build ~ '-linux-amd64.deb'", package_url)
        checksum_default = self.defaults.get(prefix + "package_checksum", "")
        self.assertIn("10.6.1.1", checksum_default)
        self.assertIn("b2ae2962645c", checksum_default)
        self.assertIn("else ''", checksum_default)
        self.assertIn("sha512:2172ed26173b4f29e3ffb051800dce3b21701f8fa202466063a535dd9e7c2cac03714e5db026c4a5dd37249a23be017661a80b4969a339e1d653a16622180c31", checksum_default)
        self.assertEqual(self.defaults.get("splunk_version"), "10.6.1.1")
        self.assertIs(self.defaults.get("splunk_accept_license"), False)
        self.assertEqual(self.defaults.get("splunk_receiver_ip"), "")
        self.assertEqual(self.defaults.get("splunk_receiver_port"), 9997)
        self.assertEqual(self.defaults.get(prefix + "admin_user"), "admin")
        self.assertEqual(self.defaults.get("splunk_forwarder_linux_admin_password"), "SplunkLab-ChangeMe1!")
        self.assertEqual(
            self.defaults.get(prefix + "monitors"),
            [{"path": "/var/log/laurel/audit.log", "sourcetype": "laurel:json", "index": "main"}],
        )

    def test_shared_inputs_and_linux_forwarder_namespace_contract(self):
        self.assertEqual(self.defaults.get("splunk_version"), "10.6.1.1")
        self.assertEqual(self.defaults.get("splunk_build"), "b2ae2962645c")
        self.assertIs(self.defaults.get("splunk_accept_license"), False)
        self.assertEqual(self.defaults.get("splunk_receiver_ip"), "")
        self.assertEqual(self.defaults.get("splunk_receiver_port"), 9997)
        self.assertEqual(self.defaults.get("splunk_forwarder_admin_user"), "admin")
        self.assertEqual(
            {value for key, value in self.defaults.items() if key.endswith("admin_password")},
            {"SplunkLab-ChangeMe1!", "Changeme1!"},
            "preserve the existing Linux and Windows password defaults",
        )
        self.assertFalse(any(key.startswith(("ludus_splunk_collector_", "splunk_uf_", "splunk_admin_"))
                             for key in self.defaults), "legacy public input aliases must be removed")
        self.assertTrue(any(key.startswith("splunk_forwarder_") for key in self.defaults))

        validation = [index for index, task in enumerate(self.linux_tasks)
                      if any("splunk_accept_license" in expression
                             for expression in _assertion_expressions(task))]
        mutation_modules = {"apt", "get_url", "user", "group", "file", "template", "copy",
                            "systemd_service", "command"}
        mutations = [index for index, task in enumerate(self.linux_tasks)
                     if any(_module(task, module) is not None for module in mutation_modules)]
        self.assertTrue(validation, "Linux branch must explicitly validate shared license acceptance")
        self.assertTrue(mutations, "Linux branch mutation tasks missing")
        self.assertLess(min(validation), min(mutations), "license gate must precede Linux mutation")

        seed_template = (ROLE / "templates/user-seed.conf.j2").read_text()
        outputs_template = (ROLE / "templates/outputs.conf.j2").read_text()
        self.assertIn("splunk_forwarder_admin_user", seed_template)
        self.assertIn("splunk_forwarder_", seed_template)
        self.assertIn("splunk_receiver_ip", outputs_template)
        self.assertIn("splunk_forwarder_receiver_port", outputs_template)
        self.assertIn("ludus_collector", self.source, "persisted Linux app path/marker must remain unchanged")
        self.assertIn("ludus-managed.conf", self.source)
        self.assertIn("/opt/splunkforwarder/etc/apps/ludus_collector/local", self.source)

    def test_metadata_declares_consolidated_role_identity_and_supported_platforms(self):
        info = self.meta.get("galaxy_info", {})
        self.assertEqual(info.get("author"), "dotknewt")
        self.assertEqual(info.get("role_name"), "splunk_forwarder")
        self.assertEqual(info.get("min_ansible_version"), "2.16")
        platforms = {(item.get("name"), tuple(item.get("versions", [])))
                     for item in info.get("platforms", [])}
        linux_platforms = {platform for platform in platforms if platform[0] != "Windows"}
        self.assertEqual(linux_platforms,
                         {("Debian", ("trixie",)), ("Ubuntu", ("noble", "resolute"))})
        # Galaxy's metadata schema does not allow Windows 11 as a version token;
        # runtime validation separately admits Windows 11 plus these Server versions.
        self.assertEqual({platform for platform in platforms if platform[0] == "Windows"},
                         {("Windows", ("2019", "2022", "2025"))})
        self.assertEqual(self.meta.get("dependencies"), [])

    def test_platform_license_and_injected_inputs_are_checked_before_mutation(self):
        expressions = [expression for task in self.linux_tasks for expression in _assertion_expressions(task)]
        joined = "\n".join(expressions)
        for expression in (
            'ansible_architecture == "x86_64"', 'ansible_service_mgr == "systemd"',
            "splunk_accept_license", "splunk_receiver_ip",
            "splunk_receiver_port", "splunk_forwarder_monitors",
            "is boolean",
        ):
            self.assertIn(expression, joined)
        self.assertRegex(joined, r"https://")
        self.assertRegex(joined, r"(?:@|\[\^/@\])")
        self.assertRegex(joined, r"(?:unique|difference|count\(\).{0,80}length|length.{0,80}count\(\))")
        for filter_name in (
            "ludus_splunk_collector_valid_monitor_path",
            "ludus_splunk_collector_valid_sourcetype",
            "ludus_splunk_collector_valid_index",
            "ludus_splunk_collector_valid_receiver_host",
            "ludus_splunk_collector_valid_username",
        ):
            self.assertIn(filter_name, joined)
        guarded = [index for index, task in enumerate(self.linux_tasks)
                      if any("splunk_accept_license" in expr for expr in _assertion_expressions(task))]
        mutations = [index for index, task in enumerate(self.linux_tasks)
                     if any(_module(task, module) is not None for module in ("apt", "get_url", "user", "group", "file", "template"))]
        self.assertTrue(guarded, "missing license/input validation assertions")
        self.assertTrue(mutations, "missing package/identity mutation tasks")
        self.assertLess(min(guarded), min(mutations), "input/license guards must precede mutation")
        credential_checks = [task for task in self.linux_tasks
                             if any("splunk_forwarder_admin_user" in expr or "splunk_forwarder_linux_admin_password" in expr
                                    for expr in _assertion_expressions(task))]
        self.assertTrue(credential_checks, "missing credential assertion task")
        self.assertTrue(any(task.get("no_log") is True for task in credential_checks),
                        "credential assertion task must set no_log: true")

    def test_receiver_port_is_strictly_validated_normalized_and_used_by_linux_output(self):
        type_gate = next(((index, task) for index, task in enumerate(self.linux_tasks)
                          if task.get("name") == "Validate receiver port type and decimal-string format"), None)
        range_gate = next(((index, task) for index, task in enumerate(self.linux_tasks)
                           if task.get("name") == "Validate receiver port range"), None)
        normalization = next(((index, task) for index, task in enumerate(self.linux_tasks)
                              if task.get("name") == "Normalize validated Linux receiver port"), None)
        self.assertIsNotNone(type_gate, "missing strict raw receiver-port type/format validation")
        self.assertIsNotNone(range_gate, "missing receiver-port range validation")
        self.assertIsNotNone(normalization, "missing normalized internal receiver port")
        assert type_gate is not None and range_gate is not None and normalization is not None
        type_expr = "\n".join(_assertion_expressions(type_gate[1]))
        range_expr = "\n".join(_assertion_expressions(range_gate[1]))

        self.assertIn("splunk_receiver_port is integer", type_expr)
        self.assertIn("splunk_receiver_port is not boolean", type_expr)
        self.assertIn("splunk_receiver_port is string", type_expr)
        self.assertIn("[0-9]", type_expr)
        self.assertIn(r"\Z", type_expr, "decimal strings must be fully matched, excluding final newlines")
        self.assertNotIn("$", type_expr, "regex must not accept a final newline")
        self.assertLess(type_gate[0], range_gate[0], "type/format rejection must precede numeric coercion")
        self.assertIn("splunk_receiver_port | int", range_expr)
        self.assertRegex(range_expr, r">=\s*1")
        self.assertRegex(range_expr, r"<=\s*65535")
        self.assertLess(range_gate[0], normalization[0], "normalize only after type and range validation")
        normalize_set_fact = _module(normalization[1], "set_fact")
        self.assertIsNotNone(normalize_set_fact)
        self.assertIn("splunk_forwarder_receiver_port", normalize_set_fact)
        output = (ROLE / "templates/outputs.conf.j2").read_text()
        self.assertIn("splunk_forwarder_receiver_port", output)
        self.assertNotIn("{{ splunk_receiver_port }}", output,
                         "Linux outputs must consume only the validated integer")

        self.assertEqual(len(_assertion_expressions(type_gate[1])), 1)
        self.assertEqual(len(_assertion_expressions(range_gate[1])), 2)
        expression_env = NativeEnvironment()
        expression_env.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
        type_check = expression_env.compile_expression(_assertion_expressions(type_gate[1])[0])
        range_checks = [expression_env.compile_expression(expression)
                        for expression in _assertion_expressions(range_gate[1])]
        cases = (
            (9997, True, True),
            ("9997", True, True),
            (0, True, False),
            (65536, True, False),
            ("0", True, False),
            ("65536", True, False),
            (True, False, None),
            (False, False, None),
            (9997.0, False, None),
            ("9997.0", False, None),
            (" 9997", False, None),
            ("9997\n", False, None),
            ("+9997", False, None),
            ("", False, None),
            (None, False, None),
            ([9997], False, None),
        )
        for value, expected_type, expected_range in cases:
            with self.subTest(receiver_port=value):
                self.assertIs(type_check(splunk_receiver_port=value), expected_type)
                if expected_range is not None:
                    actual_range = all(check(splunk_receiver_port=value) for check in range_checks)
                    self.assertIs(actual_range, expected_range)

    def test_package_metadata_and_existing_state_fail_closed(self):
        for value in (
            "dpkg-deb",
            "splunkforwarder", "amd64", "nologin", "/opt/splunkforwarder",
            "SplunkForwarder.service", "CAP_", "validate_forwarder_unit_execs",
        ):
            self.assertIn(value, self.source)
        self.assertIn("allow_downgrade: false", self.source)
        self.assertIn("validate_certs: true", self.source)
        metadata_commands = [
            _module(task, "command") for task in self.flat_tasks
            if _module(task, "command") is not None
            and _module(task, "command").get("argv", [None])[0] == "dpkg-deb"
        ]
        self.assertTrue(metadata_commands, "missing parsed dpkg-deb metadata command")
        for command in metadata_commands:
            self.assertEqual(command["argv"][1], "-W")
            self.assertEqual(command["argv"][2], "--showformat=${Package}\\n${Version}\\n${Architecture}\\n")
            self.assertIs(command.get("expand_argument_vars"), False)
        package_checks = [index for index, task in enumerate(self.ordered_tasks)
                          if any("splunkforwarder" in expr and "amd64" in expr for expr in _assertion_expressions(task))]
        package_installs = [index for index, task in enumerate(self.ordered_tasks)
                            if _module(task, "apt") is not None]
        self.assertTrue(package_checks, "missing exact package metadata assertions")
        self.assertTrue(package_installs, "missing package installation task")
        self.assertLess(min(package_checks), min(package_installs), "package identity must be checked before installation")
        self.assertNotIn("include_role:", self.source)
        self.assertNotIn("import_role:", self.source)

    def test_installed_identity_and_auth_database_are_preflighted(self):
        assertions = "\n".join(expr for task in self.flat_tasks for expr in _assertion_expressions(task))
        self.assertIn("splunk_forwarder_installed.rc != 0 or (splunk_forwarder_user_record.rc == 0 and splunk_forwarder_group_record.rc == 0)", assertions)
        self.assertIn("splunk_forwarder_path_state.passwd.get('isreg', false)", assertions)
        self.assertIn("splunk_forwarder_path_state.passwd.get('size', 0) | int > 0", assertions)
        for ancestor in ("etc", "apps", "app_local", "system", "system_local"):
            self.assertIn(f"splunk_forwarder_path_state.{ancestor}.get('islnk', false)", assertions)

    def test_seed_is_fresh_only_protected_and_cleaned_after_auth_readiness(self):
        for value in (
            "user-seed.conf", "passwd", "mode: \"0600\"", "no_log: true", "diff: false",
            "use_proxy: false", "follow_redirects: none",
        ):
            self.assertIn(value, self.source)
        ordered_text = "\n".join(str(task) for task in self.ordered_tasks)
        self.assertIn("passwd", ordered_text)
        self.assertIn("seed_created.changed", ordered_text)
        authenticated_tasks = [
            (index, task) for index, task in enumerate(self.linux_tasks)
            if _module(task, "uri") is not None
            and _module(task, "uri").get("url") == "http://localhost:8089/services/server/info?output_mode=json"
            and _module(task, "uri").get("unix_socket") == "/opt/splunkforwarder/var/run/splunk/cli.socket"
            and _module(task, "uri").get("status_code") == 200
            and _module(task, "uri").get("user") == "{{ splunk_forwarder_admin_user }}"
            and _module(task, "uri").get("password") == "{{ splunk_forwarder_linux_admin_password }}"
            and _module(task, "uri").get("force_basic_auth") is True
        ]
        cleanup_indices = [index for index, task in enumerate(self.linux_tasks)
                           if _module(task, "file") is not None and _module(task, "file").get("state") == "absent"
                           and "user-seed.conf" in str(_module(task, "file"))]
        self.assertTrue(authenticated_tasks, "missing authenticated Unix-socket readiness check")
        for auth_index, auth_task in authenticated_tasks:
            self.assertIs(auth_task.get("no_log"), True, "authenticated readiness must not log credentials")
            self.assertIn("splunk_forwarder_seed_created.changed", str(auth_task.get("when", "")),
                          "fresh authentication must be limited to a seed created by this invocation")
        self.assertTrue(cleanup_indices, "missing seed cleanup task")
        self.assertLess(min(index for index, _ in authenticated_tasks), min(cleanup_indices),
                        "seed cleanup must follow authenticated readiness")

    def test_owned_forwarding_config_is_validated_and_convergent(self):
        for value in ("ludus_collector", "[tcpout]", "[monitor://", "sourcetype", "index"):
            self.assertIn(value, self.source)
        marker_assertions = [expr for task in self.flat_tasks for expr in _assertion_expressions(task)
                             if "marker" in expr.lower() or "ownership" in expr.lower()]
        self.assertTrue(marker_assertions, "missing ownership-marker preflight assertion")
        writers = [task for task in self.flat_tasks for module in ("template", "copy")
                   if _module(task, module) is not None
                   and any(name in str(_module(task, module).get("dest", "")) for name in ("inputs.conf", "outputs.conf"))]
        written_destinations = {str(_module(task, module).get("dest", ""))
                                for task in writers for module in ("template", "copy")
                                if _module(task, module) is not None}
        self.assertTrue(any("inputs.conf" in dest for dest in written_destinations), "missing owned inputs.conf writer")
        self.assertTrue(any("outputs.conf" in dest for dest in written_destinations), "missing owned outputs.conf writer")
        service_tasks = [task for task in self.flat_tasks if _module(task, "systemd_service") is not None]
        service_args = [_module(task, "systemd_service") for task in service_tasks]
        self.assertTrue(any(args.get("name") == "SplunkForwarder.service" and args.get("state") == "started" for args in service_args),
                        "missing dedicated service start")
        restart_tasks = [task for task in self.flat_tasks if _module(task, "systemd_service") is not None
                         and _module(task, "systemd_service").get("name") == "SplunkForwarder.service"
                         and _module(task, "systemd_service").get("state") == "restarted"]
        handler_names = {value for task in restart_tasks for value in (task.get("name"), task.get("listen")) if value}
        notified = {notify for task in writers for notify in ([task.get("notify")] if isinstance(task.get("notify"), str) else task.get("notify", []))}
        self.assertTrue(notified & handler_names, "configuration writers must notify a restart handler")
        self.assertTrue(restart_tasks, "missing change-triggered service restart handler")
        self.assertNotRegex(self.source, r"(?i)(?:ufw|firewall|iptables|firewalld)")

    def test_readme_states_platform_usage_and_verification_limits(self):
        readme_path = ROLE / "README.md"
        self.assertTrue(readme_path.exists())
        readme = re.sub(r"\s+", " ", readme_path.read_text()) if readme_path.exists() else ""
        for value in (
            "Debian 13", "Ubuntu 24.04", "Ubuntu 26.04", "x86_64", "systemd",
            "splunk_forwarder_", "splunk_server_", "splunk_accept_license",
            "not verified", "input-driven", "SILK",
        ):
            self.assertIn(value, readme)

    def test_task_module_arguments_and_handler_privilege_are_structurally_valid(self):
        for task in self.flat_tasks:
            self.assertNotIn("fail_msg", task, f"fail_msg must be nested inside its module arguments: {task.get('name')}")
            assert_args = _module(task, "assert")
            if assert_args is not None:
                self.assertIsInstance(assert_args, dict, task.get("name"))
                self.assertIsInstance(assert_args.get("that"), (str, list), task.get("name"))

        restart_handlers = [task for task in self.flat_tasks
                            if _module(task, "systemd_service") is not None
                            and _module(task, "systemd_service").get("state") == "restarted"]
        self.assertTrue(restart_handlers, "missing forwarder restart handler")
        self.assertTrue(all(task.get("become") is True for task in restart_handlers),
                        "systemd restart handler must escalate privileges")

    def test_role_imports_are_static_scalar_files_and_handlers_flush_before_readiness(self):
        import_tasks = [task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
                        for task in _flatten(self.tasks)
                        if "ansible.builtin.import_tasks" in task or "import_tasks" in task]
        self.assertTrue(import_tasks, "role entrypoint must import focused task files")
        for imported in import_tasks:
            self.assertIsInstance(imported, str, "import_tasks must use static scalar paths")
            self.assertNotIn("{{", imported, "dynamic task inclusion is not statically orderable")
            self.assertTrue((ROLE / "tasks" / imported).is_file(), f"unresolved task import: {imported}")

        linux_sequence = self.linux_tasks
        flushes = [index for index, task in enumerate(linux_sequence)
                   if _module(task, "meta") == "flush_handlers"]
        starts = [index for index, task in enumerate(linux_sequence)
                  if _module(task, "systemd_service") is not None
                  and _module(task, "systemd_service").get("state") == "started"]
        readiness = [index for index, task in enumerate(linux_sequence)
                     if _module(task, "wait_for") is not None or _module(task, "uri") is not None]
        self.assertTrue(flushes, "missing handler flush before readiness")
        self.assertTrue(starts, "missing forwarder start")
        self.assertTrue(readiness, "missing listener/auth readiness checks")
        self.assertLess(max(starts), min(flushes))
        self.assertLess(max(flushes), min(readiness), "queued restarts must finish before readiness is checked")

    def test_syntax_harness_is_target_safe_and_supplies_only_syntax_inputs(self):
        self.assertEqual(len(self.syntax), 1, "missing tests/syntax.yml play")
        play = self.syntax[0]
        self.assertEqual(play.get("hosts"), "localhost")
        self.assertFalse(play.get("gather_facts", True))
        pre_tasks = play.get("pre_tasks", [])
        self.assertTrue(pre_tasks, "syntax harness must stop before role execution")
        self.assertTrue(any(_module(task, "fail") is not None for task in pre_tasks),
                        "syntax harness pre-task must fail during ordinary execution")
        roles = play.get("roles", [])
        self.assertEqual([role.get("role") for role in roles], ["dotknewt.splunk_forwarder"])
        inputs = play.get("vars", {})
        self.assertTrue(inputs.get("splunk_accept_license"))
        self.assertEqual(inputs.get("splunk_receiver_ip"), "127.0.0.1")
        self.assertTrue(inputs.get("splunk_forwarder_linux_admin_password"))
        self.assertNotEqual(inputs.get("splunk_forwarder_linux_admin_password"), "SplunkLab-ChangeMe1!")

    def test_exact_vendor_unit_and_monitor_lexical_contracts(self):
        parser_path = ROLE / "filter_plugins/collector_unit.py"
        spec = importlib.util.spec_from_file_location("collector_unit", parser_path)
        parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(parser)

        vendor_unit = """[Service]
ExecStart=/opt/splunkforwarder/bin/splunk _internal_launch_under_systemd
ExecStartPre=-/bin/bash -c "chown -R splunkfwd:splunkfwd /opt/splunkforwarder"
ExecStartPost=-/bin/bash -c "chown -R splunkfwd:splunkfwd /sys/fs/cgroup/cpu/system.slice/%n"
ExecStartPost=-/bin/bash -c "chown -R splunkfwd:splunkfwd /sys/fs/cgroup/memory/system.slice/SplunkForwarder.service"
"""
        self.assertTrue(parser.validate_forwarder_unit_execs(vendor_unit))
        direct_chown = vendor_unit.replace(
            '-/bin/bash -c "chown -R splunkfwd:splunkfwd /opt/splunkforwarder"',
            "-/bin/chown -R splunkfwd:splunkfwd /opt/splunkforwarder",
        )
        self.assertTrue(parser.validate_forwarder_unit_execs(direct_chown))
        for rejected in (
            vendor_unit.replace("/opt/splunkforwarder/bin/splunk", "/tmp/evil"),
            vendor_unit.replace("ExecStartPre=-/bin/bash", "ExecStartPre=+/bin/bash"),
            vendor_unit + "ExecStartPost=/bin/sh -c 'touch /tmp/pwned'\n",
            vendor_unit + "ExecStart=/tmp/extra\n",
            vendor_unit.replace(
                'chown -R splunkfwd:splunkfwd /opt/splunkforwarder"',
                'chown -R splunkfwd:splunkfwd /opt/splunkforwarder; touch /tmp/pwned"',
            ),
            vendor_unit.replace(
                'chown -R splunkfwd:splunkfwd /opt/splunkforwarder"',
                'chown -R splunkfwd:splunkfwd $(touch /tmp/pwned)"',
            ),
            vendor_unit.replace(
                'chown -R splunkfwd:splunkfwd /opt/splunkforwarder"',
                'chown -R splunkfwd:splunkfwd /etc"',
            ),
        ):
            with self.subTest(unit=rejected):
                self.assertNotEqual(rejected, vendor_unit, "negative fixture must change the valid unit")
                self.assertFalse(parser.validate_forwarder_unit_execs(rejected))

        self.assertTrue(parser.valid_monitor_path("/var/log/laurel/audit.log"))
        for invalid in (
            "relative/path", "/var/log/*/audit.log", "/var/log/.../audit.log",
            "/var/log/./audit.log", "/var/log/../etc/shadow", "/var//log/file",
            "/var/log/file/", "/var/log/with\\slash", "/var/log/[abc]",
            "/var/log/file\noutputs.conf", "/var/log/control\x00char",
        ):
            self.assertFalse(parser.valid_monitor_path(invalid), invalid)
        self.assertTrue(parser.valid_sourcetype("laurel:json"))
        self.assertFalse(parser.valid_sourcetype("laurel:json\n"))
        self.assertTrue(parser.valid_index("main"))
        self.assertFalse(parser.valid_index("main\r"))
        self.assertTrue(parser.valid_receiver_host("receiver.example.test"))
        self.assertFalse(parser.valid_receiver_host("receiver.example.test\n"))
        self.assertTrue(parser.valid_username("admin.lab-1"))
        self.assertFalse(parser.valid_username("admin\n[evil]"))


if __name__ == "__main__":
    unittest.main()
