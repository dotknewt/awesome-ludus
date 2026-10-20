"""Static contracts for independently managed Splunk indexes; no host is simulated."""

from pathlib import Path
import importlib.util
import re
import unittest

import yaml
from jinja2 import Environment, StrictUndefined


ROLE = Path(__file__).resolve().parents[1]
APP = "/opt/splunk/etc/apps/ludus_indexes"
MARKER = f"{APP}/.ludus-managed.json"
CONFIG = f"{APP}/local/indexes.conf"


def _task_sequence(tasks, base_dir=None, inherited_when=()):
    """Flatten real static imports, skipping not-yet-created files during red phase."""
    base_dir = base_dir or (ROLE / "tasks")
    for task in tasks or []:
        when = task.get("when")
        effective_when = (*inherited_when, *((when,) if isinstance(when, str) else (when or ())))
        module = next(
            ((name, value) for name, value in task.items()
             if name in {"import_tasks", "ansible.builtin.import_tasks"}),
            (None, None),
        )
        if module[0]:
            value = module[1]
            imported = value.get("file") if isinstance(value, dict) else value
            if isinstance(imported, str) and "{{" not in imported:
                path = base_dir / imported
                if path.is_file():
                    yield from _task_sequence(yaml.safe_load(path.read_text()), path.parent, effective_when)
            continue
        yield {**task, "__effective_when": list(effective_when)}
        for key in ("block", "rescue", "always"):
            yield from _task_sequence(task.get(key, []), base_dir, effective_when)


def _module(task):
    return next(
        ((name, value) for name, value in task.items()
         if name.startswith("ansible.builtin.")),
        (None, None),
    )


def _index_sources():
    paths = [ROLE / "tasks/indexes_preflight.yml", ROLE / "tasks/indexes_configure.yml",
             ROLE / "templates/indexes.conf.j2"]
    helper_dir = ROLE / "filter_plugins"
    if helper_dir.is_dir():
        paths.extend(path for pattern in ("index*.py", "indexes*.py")
                     for path in helper_dir.glob(pattern))
    return "\n".join(path.read_text() for path in paths if path.is_file())


def _index_task_sequence(filename):
    path = ROLE / "tasks" / filename
    if not path.is_file():
        return []
    return list(_task_sequence(yaml.safe_load(path.read_text()), path.parent))


def _ordered_main_tasks(tasks):
    """Flatten blocks but retain static imports as nodes for main-order checks."""
    for task in tasks or []:
        yield task
        for key in ("block", "rescue", "always"):
            yield from _ordered_main_tasks(task.get(key, []))


def _parse_indexes_conf(rendered):
    """Parse rendered INI stanzas for assertions over the real Jinja template."""
    stanzas = {}
    current = None
    for line in rendered.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            stanzas[current] = {}
        elif current is not None and "=" in line:
            key, value = line.split("=", 1)
            stanzas[current][key.strip()] = value.strip()
    return stanzas


class SplunkServerIndexesStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text()) or {}
        cls.main_tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text()) or []

    def test_server_indexes_are_append_only(self):
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        self.assertIn("ludus_splunk_server_indexes", defaults)
        self.assertEqual(defaults["ludus_splunk_server_indexes"], [])

        source = _index_sources()
        preflight_tasks = _index_task_sequence("indexes_preflight.yml")
        validation_assertions = [str(_module(task)[1].get("that", []))
                                 for task in preflight_tasks
                                 if _module(task)[0] == "ansible.builtin.assert"
                                 and "ludus_splunk_server_indexes" in str(_module(task)[1].get("that", []))]
        self.assertTrue(validation_assertions,
                        "index input validation must be a concrete preflight assertion")
        validation = " ".join(validation_assertions).lower()
        for path in (MARKER, CONFIG, "/opt/splunk/var/lib/splunk"):
            self.assertIn(path, source)
        self.assertNotIn("$SPLUNK_DB", source)
        for directory in ("db", "colddb", "thaweddb"):
            self.assertIn(directory, source)
        self.assertIn("schema_version", source)
        self.assertIn("indexes", source)
        self.assertRegex(source, r"schema_version.{0,8}1")

        # Validate through a full-string operation, not an end-$ anchor, which
        # accepts a final newline. The validator must also reject duplicate names.
        self.assertRegex(validation + " " + source.lower(), r"fullmatch|\\z|validate_[a-z_]*indexes")
        for reserved in ("main", "history", "summary"):
            self.assertIn(reserved, validation + " " + source.lower())
        self.assertRegex(validation + " " + source.lower(), r"default|internal")
        self.assertRegex(validation + " " + source.lower(), r"duplicate|unique|distinct")
        self.assertRegex(source.lower(), r"(owned|managed).{0,240}issubset.{0,120}requested|"
                                         r"(requested|desired|configured|indexes).{0,240}(owned|managed).{0,240}(subset|remove|append|issubset|difference)|"
                                r"(owned|managed).{0,240}(requested|desired|configured|indexes).{0,240}(subset|remove|append|issubset|difference)",
                         msg="a formerly managed index, including a request of [], must fail removal")

    def test_empty_default_is_a_noop_but_managed_empty_removal_is_rejected(self):
        self.assertEqual(self.defaults.get("ludus_splunk_server_indexes"), [])
        configure_tasks = _index_task_sequence("indexes_configure.yml")
        self.assertTrue(configure_tasks, "index configuration tasks must be isolated in their own task file")
        mutators = [task for task in configure_tasks
                    if _module(task)[0] in {"ansible.builtin.template", "ansible.builtin.copy",
                                            "ansible.builtin.file"}]
        self.assertTrue(mutators)
        ordered = list(_ordered_main_tasks(self.main_tasks))
        configure_import_conditions = [str(task.get("when", "")).lower()
                                       for task in ordered
                                       if _module(task)[0] == "ansible.builtin.import_tasks"
                                       and ((_module(task)[1].get("file")
                                             if isinstance(_module(task)[1], dict)
                                             else _module(task)[1]) == "indexes_configure.yml")]
        self.assertTrue(configure_import_conditions,
                        "main must import the index configure task file")
        for task in mutators:
            conditions = (str(task.get("__effective_when", [])) + " "
                          + " ".join(configure_import_conditions)).lower()
            self.assertTrue(conditions, "empty, never-managed indexes must not create the app")
            self.assertTrue("ludus_splunk_server_indexes" in conditions
                            or "owned" in conditions or "managed" in conditions)

        source = _index_sources()
        self.assertRegex(source.lower(), r"schema_version.{0,120}indexes|indexes.{0,120}schema_version")
        self.assertRegex(source, r"(owned|managed).{0,240}issubset.{0,120}requested|"
                                r"(requested|desired|configured|indexes).{0,240}(owned|managed).{0,240}(subset|remove|append|issubset|difference)|"
                                r"(owned|managed).{0,240}(requested|desired|configured|indexes).{0,240}(subset|remove|append|issubset|difference)",
                         msg="a formerly managed index must fail removal, including a request of []")

        ordered = list(_ordered_main_tasks(self.main_tasks))
        def imported_file(task):
            value = _module(task)[1]
            return value.get("file") if isinstance(value, dict) else value

        preflight_imports = [index for index, task in enumerate(ordered)
                             if _module(task)[0] == "ansible.builtin.import_tasks"
                             and imported_file(task) == "indexes_preflight.yml"]
        configure_imports = [index for index, task in enumerate(ordered)
                             if _module(task)[0] == "ansible.builtin.import_tasks"
                             and imported_file(task) == "indexes_configure.yml"]
        first_mutations = [index for index, task in enumerate(ordered)
                           if _module(task)[0] in {"ansible.builtin.file", "ansible.builtin.copy",
                                                  "ansible.builtin.template", "ansible.builtin.apt",
                                                  "ansible.builtin.get_url", "ansible.builtin.user",
                                                  "ansible.builtin.group"}]
        self.assertTrue(preflight_imports, "main must import index preflight")
        self.assertTrue(first_mutations, "existing main mutation boundary must remain visible")
        self.assertLess(min(preflight_imports), min(first_mutations),
                        "index preflight import must precede the existing first-mutating block")
        starts = [index for index, task in enumerate(ordered)
                  if _module(task)[0] == "ansible.builtin.systemd_service"
                  and isinstance(_module(task)[1], dict)
                  and _module(task)[1].get("state") in {"started", "restarted"}]
        self.assertTrue(configure_imports, "main must import index configuration")
        self.assertTrue(starts, "main service-start boundary must remain visible")
        self.assertLess(min(configure_imports), min(starts),
                        "index configuration import must precede service start/restart")

    def test_empty_never_managed_state_skips_conflict_scans_but_owned_removal_guard_runs(self):
        tasks = _index_task_sequence("indexes_preflight.yml")
        self.assertTrue(tasks)
        conflict_scans = [
            (index, task) for index, task in enumerate(tasks)
            if (_module(task)[0] == "ansible.builtin.find"
                and ("indexes.conf" in str(_module(task)[1])
                     or (_module(task)[1].get("paths") == "/opt/splunk/etc"
                         and _module(task)[1].get("file_type") == "link")))
            or (_module(task)[0] == "ansible.builtin.slurp"
                and "ludus_splunk_server_index_existing_configs" in str(task.get("loop", "")))
        ]
        self.assertTrue(conflict_scans, "full index.conf conflict scans must be explicit")
        for _, task in conflict_scans:
            conditions = " ".join(map(str, task.get("__effective_when", []))).lower()
            self.assertIn("ludus_splunk_server_indexes", conditions)
            self.assertIn("length", conditions)
            self.assertIn("> 0", conditions,
                          "never-managed [] must bypass recursive config scans and reads")

        append_guards = [(index, task) for index, task in enumerate(tasks)
                         if _module(task)[0] == "ansible.builtin.assert"
                         and "marker_allows_append" in str(_module(task)[1].get("that", []))]
        self.assertTrue(append_guards, "owned-list removal must have an explicit append-only guard")
        append_index, append_guard = append_guards[0]
        append_when = str(append_guard.get("__effective_when", [])).lower()
        self.assertIn("exists", append_when)
        self.assertNotIn("indexes | length", append_when,
                         "the owned-empty request must reach the removal guard")
        self.assertLess(append_index, min(index for index, _ in conflict_scans),
                        "an owned [] removal fails before any full conflict scan")

    def test_index_preflight_rejects_symlinked_directories_across_config_tree(self):
        tasks = _index_task_sequence("indexes_preflight.yml")
        scans = [(task.get("register"), _module(task)[1]) for task in tasks
                 if _module(task)[0] == "ansible.builtin.find"
                 and isinstance(_module(task)[1], dict)
                 and _module(task)[1].get("paths") == "/opt/splunk/etc"
                 and _module(task)[1].get("file_type") == "link"]
        self.assertTrue(scans, "all config-tree links, including directory links, must be inspected")
        for register, args in scans:
            self.assertFalse(args.get("patterns"), "do not restrict link discovery to indexes.conf files")
            self.assertIs(args.get("follow"), False)
            coverage_guards = [task for task in tasks
                               if _module(task)[0] == "ansible.builtin.assert"
                               and register in str(_module(task)[1].get("that", []))]
            self.assertTrue(coverage_guards,
                            "the discovered symlink directories/files must be rejected")
            self.assertIn("skipped_paths", str(_module(coverage_guards[0])[1].get("that", [])),
                          "incomplete or unreadable no-follow scans must fail closed")

    def test_all_index_conflicts_and_symlink_ancestors_are_preflighted_before_mutation(self):
        preflight_tasks = _index_task_sequence("indexes_preflight.yml")
        configure_tasks = _index_task_sequence("indexes_configure.yml")
        self.assertTrue(preflight_tasks, "index-specific preflight task file is required")
        stats = []
        assertions = []
        for index, task in enumerate(preflight_tasks):
            module, args = _module(task)
            if module == "ansible.builtin.stat":
                stats.append((index, args if isinstance(args, dict) else {}))
            if module == "ansible.builtin.assert":
                assertions.append((index, str(args.get("that", []))))

        self.assertTrue(assertions, "index ownership/conflict guards must be real assertions")
        self.assertTrue(stats, "preflight must inspect existing app/config/data state")
        self.assertTrue(all(args.get("follow") is False for _, args in stats),
                        "inspect paths without following symlinks")
        guards = " ".join(text for _, text in assertions).lower()
        source = _index_sources()
        for token in ("ludus_indexes", ".ludus-managed.json", "indexes.conf"):
            self.assertIn(token, source)
        self.assertRegex(guards, r"islnk|symlink")
        self.assertRegex(guards, r"marker|managed|owned")
        marker_stats = [(index, task) for index, task in enumerate(preflight_tasks)
                        if _module(task)[0] == "ansible.builtin.stat"
                        and ("marker" in str(task.get("name", "")).lower()
                             or ".ludus-managed.json" in str(_module(task)[1]))]
        self.assertTrue(marker_stats, "preflight must stat the authoritative index marker")
        marker_registers = [task.get("register") for _, task in marker_stats if task.get("register")]
        self.assertTrue(marker_registers, "marker stat must be registered for its ownership guard")
        marker_guards = [str(args) for _, args in assertions
                         if any(register in str(args) for register in marker_registers)]
        self.assertTrue(marker_guards, "assertions must check the marker stat rather than unrelated guards")
        self.assertRegex(" ".join(marker_guards).lower(), r"exists|islnk|schema_version|indexes")

        local_mutations = [index for index, task in enumerate(preflight_tasks)
                           if _module(task)[0] in {"ansible.builtin.template", "ansible.builtin.copy",
                                                  "ansible.builtin.file", "ansible.builtin.lineinfile",
                                                  "ansible.builtin.blockinfile"}]
        if local_mutations:
            self.assertLess(max(index for index, _ in assertions), min(local_mutations),
                            "index-specific preflight guards precede index-specific mutations")

        collision_assertions = [task for task in preflight_tasks
                                if _module(task)[0] == "ansible.builtin.assert"
                                and "ludus_splunk_server_index_existing_config_contents" in str(task.get("loop", ""))]
        self.assertTrue(collision_assertions,
                        "collision assertions must iterate the collected competing indexes.conf files")
        for task in collision_assertions:
            expression = str(_module(task)[1].get("that", []))
            self.assertIn("intersect", expression)
            self.assertIn("length", expression)
            self.assertIn("== 0", expression,
                          "the requested-name intersection with each competing file must be empty")
            self.assertIn("item.content", expression)
            conditions = " ".join(map(str, task.get("__effective_when", [])))
            self.assertIn("ludus_splunk_server_indexes", conditions)
            self.assertIn("> 0", conditions)
            self.assertIn("item.item.path", conditions,
                          "the owned config is excluded while unmanaged definitions are checked")

    def test_configuration_is_additive_without_unmanaged_overwrite_or_data_retention_removal(self):
        tasks = _index_task_sequence("indexes_preflight.yml") + _index_task_sequence("indexes_configure.yml")
        modules = [_module(task)[0] for task in tasks]
        self.assertNotIn("ansible.builtin.lineinfile", modules,
                         "do not edit arbitrary pre-existing index stanzas")
        self.assertNotIn("ansible.builtin.blockinfile", modules,
                         "do not rewrite unmanaged index configuration")

        absent = [task for task in tasks if _module(task)[0] == "ansible.builtin.file"
                  and isinstance(_module(task)[1], dict)
                  and _module(task)[1].get("state") == "absent"]
        for task in absent:
            self.assertNotRegex(str(_module(task)[1].get("path", "")),
                                r"\$SPLUNK_DB|/db(?:/|$)|/colddb(?:/|$)|/thaweddb(?:/|$)")

        config_source = (ROLE / "templates/indexes.conf.j2")
        self.assertTrue(config_source.is_file(), "render the actual managed indexes template")
        rendered = Environment(undefined=StrictUndefined).from_string(config_source.read_text()).render(
            ludus_splunk_server_indexes=["winlogs", "sysmon", "etw"],
        )
        stanzas = _parse_indexes_conf(rendered)
        self.assertEqual(set(stanzas), {"winlogs", "sysmon", "etw"})
        expected = {
            index_name: {
                "homePath": f"/opt/splunk/var/lib/splunk/{index_name}/db",
                "coldPath": f"/opt/splunk/var/lib/splunk/{index_name}/colddb",
                "thawedPath": f"/opt/splunk/var/lib/splunk/{index_name}/thaweddb",
            }
            for index_name in ("winlogs", "sysmon", "etw")
        }
        self.assertEqual(stanzas, expected,
                         "only the three fixed data paths are managed; no retention/settings are added")
        self.assertNotIn("$SPLUNK_DB", rendered)

    def test_config_change_is_the_only_restart_trigger_and_rendered_paths_are_owned(self):
        configure_tasks = _index_task_sequence("indexes_configure.yml")
        config_tasks = [task for task in configure_tasks
                        if CONFIG in str(_module(task)[1]) or "indexes.conf.j2" in str(_module(task)[1])]
        self.assertTrue(config_tasks, "managed config must be installed with the actual indexes template")
        self.assertTrue(any(task.get("notify") for task in config_tasks),
                        "only a changed rendered config should notify restart")
        self.assertTrue(all(task.get("changed_when") is not True for task in config_tasks),
                        "template change detection must remain Ansible's default")
        self.assertTrue(all("ludus_splunk_server_" in str(task) for task in config_tasks))

        handler_path = ROLE / "handlers/main.yml"
        handlers = list(_task_sequence(yaml.safe_load(handler_path.read_text()), ROLE / "handlers")) \
            if handler_path.is_file() else []
        restarts = [task for task in handlers
                     if _module(task)[0] == "ansible.builtin.systemd_service"
                     and isinstance(_module(task)[1], dict)
                     and _module(task)[1].get("state") == "restarted"]
        self.assertTrue(restarts)
        notified = {str(value) for task in config_tasks
                    for value in ([task.get("notify")] if isinstance(task.get("notify"), str)
                                  else task.get("notify", []))}
        self.assertTrue(any(task.get("name") in notified or task.get("listen") in notified
                            for task in restarts))
        self.assertTrue(any("active" in str(task.get("when", task.get("__effective_when", "")))
                            for task in restarts),
                        "a fresh service start must not be followed by a redundant config restart")

        source = _index_sources().lower()
        self.assertNotIn("ludus_splunk_server_receiver_host", source)
        self.assertNotIn("ludus_splunk_server_receiver_port", source)

    def test_production_index_parser_and_validator_reject_invalid_names_and_marker_drift(self):
        helper_path = ROLE / "filter_plugins/indexes_contract.py"
        self.assertTrue(helper_path.is_file(), "index validation must use the production pure helper")
        spec = importlib.util.spec_from_file_location("indexes_contract", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)

        self.assertTrue(helper.indexes_valid([]))
        self.assertTrue(helper.indexes_valid(["winlogs", "sysmon", "a" * 80]))
        for invalid in (["winlogs", "winlogs"], ["winlogs\n"], ["a" * 81], ["Upper"],
                        ["main"], ["history"], ["summary"], ["default"], ["_internal"],
                        "winlogs", None):
            self.assertFalse(helper.indexes_valid(invalid), invalid)

        config = """[winlogs]
homePath = /opt/splunk/var/lib/splunk/winlogs/db
coldPath = /opt/splunk/var/lib/splunk/winlogs/colddb
thawedPath = /opt/splunk/var/lib/splunk/winlogs/thaweddb
[sysmon]
homePath = /opt/splunk/var/lib/splunk/sysmon/db
coldPath = /opt/splunk/var/lib/splunk/sysmon/colddb
thawedPath = /opt/splunk/var/lib/splunk/sysmon/thaweddb
"""
        self.assertEqual(helper.index_stanzas(config), ["winlogs", "sysmon"])
        self.assertEqual(helper.index_stanzas("[winlogs]\n[winlogs]\n"), ["winlogs", "winlogs"])
        self.assertEqual(helper.index_stanzas("[winlogs]\nmalformed option line\n"), ["winlogs"])
        with self.assertRaises(ValueError):
            helper.index_stanzas(b"\xff")
        external_default = "[default]\nmaxTotalDataSizeMB = 1000\n[other]\nfield = value\n"
        self.assertTrue(helper.index_config_parseable(external_default))
        self.assertEqual(helper.index_stanzas(external_default), ["default", "other"])
        external_global = "globalOption = value\n[other]\nfield = value\n"
        self.assertTrue(helper.index_config_parseable(external_global))
        self.assertEqual(helper.index_stanzas(external_global), ["other"])
        external_collision = "[default]\nfield = value\n[winlogs]\nhomePath = /somewhere\n"
        self.assertTrue(helper.index_config_parseable(external_collision))
        self.assertIn("winlogs", helper.index_stanzas(external_collision))
        self.assertFalse(helper.index_config_parseable("[winlogs]\nkey = one\nkey = two\n"))
        self.assertFalse(helper.index_config_parseable("[winlogs]\n[winlogs]\n"))
        marker = '{"schema_version":1,"indexes":["winlogs","sysmon"]}'
        self.assertTrue(helper.marker_matches_config(marker, config))
        self.assertFalse(helper.marker_matches_config(marker, "[winlogs]\n"))
        self.assertTrue(helper.marker_allows_append(marker, ["winlogs", "sysmon", "etw"]))
        self.assertFalse(helper.marker_allows_append(marker, ["winlogs"]))
        self.assertFalse(helper.marker_allows_append(marker, []))

        exact_config = """[winlogs]
homePath = /opt/splunk/var/lib/splunk/winlogs/db
coldPath = /opt/splunk/var/lib/splunk/winlogs/colddb
thawedPath = /opt/splunk/var/lib/splunk/winlogs/thaweddb
"""
        one_index_marker = '{"schema_version":1,"indexes":["winlogs"]}'
        self.assertTrue(helper.marker_matches_config(one_index_marker, exact_config))
        rejected_configs = (
            exact_config.replace("/opt/splunk/var/lib/splunk/winlogs/db", "$SPLUNK_DB/winlogs/db"),
            exact_config + "frozenTimePeriodInSecs = 90\n",
            exact_config + "unknownOption = value\n",
            exact_config + "homePath = /tmp/second-home\n",
            exact_config + "[winlogs]\n",
            exact_config + "[unmanaged]\nhomePath = /tmp/other\n",
            "[DEFAULT]\ncaseSensitive = false\n" + exact_config,
            "[default]\nmaxTotalDataSizeMB = 1000\n" + exact_config,
            "globalOption = value\n" + exact_config,
            "not an indexes.conf stanza\n" + exact_config,
        )
        for invalid_config in rejected_configs:
            self.assertFalse(helper.marker_matches_config(one_index_marker, invalid_config),
                             invalid_config)
        self.assertFalse(helper.marker_matches_config(
            '{"schema_version":true,"indexes":["winlogs"]}', exact_config))
        self.assertFalse(helper.marker_allows_append(
            '{"schema_version":true,"indexes":["winlogs"]}', ["winlogs"]))
        self.assertFalse(helper.marker_matches_config(
            '{"schema_version":1,"indexes":["winlogs"],"owner":"extra"}', exact_config))
        self.assertFalse(helper.marker_matches_config(b"\xff", exact_config))
        self.assertFalse(helper.marker_matches_config(one_index_marker, b"\xff"))


if __name__ == "__main__":
    unittest.main()
