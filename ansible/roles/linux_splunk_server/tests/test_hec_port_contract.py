"""Native expression and source contracts for the public HEC port input.

The native cases execute only the port predicates extracted from the supplied
production preflight YAML on localhost. They do not import the role, contact a
guest, run a service command, or emulate Splunk state.
"""

from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import unittest

import yaml


if len(sys.argv) != 5:
    raise SystemExit(
        "usage: test_hec_port_contract.py ANSIBLE_PLAYBOOK PREFLIGHT HEC_TASKS HEC_TEMPLATE"
    )

ANSIBLE_PLAYBOOK = Path(sys.argv[1])
PREFLIGHT_PATH = Path(sys.argv[2])
HEC_TASKS_PATH = Path(sys.argv[3])
HEC_TEMPLATE_PATH = Path(sys.argv[4])
sys.argv[1:] = []

PORT_TOKEN = re.compile(r"\bsplunk_server_hec_port\b(?!_)")
NORMALIZED_PORT = re.compile(r"\bsplunk_server_hec_port\s*\|\s*int\b")

VALID = (1, 8088, 65535, "1", "08088", "65535")
INVALID = (
    True, False, None, 0, 65536, -1, 8088.0, "", " 8088", "8088 ",
    "+8088", "-1", "8088.0", "8e3", "８０８８", "8088\n", "8088\r\n",
    "8088\t", [8088], {"port": 8088},
)


def load_yaml(path, expected_type):
    if not path.is_file():
        raise AssertionError(f"missing explicit production input: {path}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise AssertionError(f"cannot load production YAML {path}: {exc}") from exc
    if not isinstance(value, expected_type):
        raise AssertionError(f"malformed production YAML {path}: expected {expected_type.__name__}")
    return value


def module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


def walk_tasks(tasks):
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            nested = task.get(section, [])
            if isinstance(nested, list):
                yield from walk_tasks(nested)


def port_predicates(tasks):
    predicates = []
    for task in walk_tasks(tasks):
        assertion = module(task, "assert")
        if not isinstance(assertion, dict):
            continue
        for condition in assertion.get("that", []):
            text = str(condition)
            if PORT_TOKEN.search(text) and "splunk_server_hec_validation_endpoint" not in text:
                predicates.append(text)
    return predicates


def task_text(task):
    return yaml.safe_dump(task, sort_keys=True)


class HecPortContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preflight = load_yaml(PREFLIGHT_PATH, list)
        cls.hec_tasks = load_yaml(HEC_TASKS_PATH, list)
        cls.predicates = port_predicates(cls.preflight)
        cls.endpoint_predicates = []
        for task in walk_tasks(cls.preflight):
            assertion = module(task, "assert")
            if isinstance(assertion, dict) and "splunk_server_hec_validation_endpoint" in task_text(task):
                cls.endpoint_predicates.extend(str(item) for item in assertion.get("that", []))

    def evaluate_native(self, variables, predicates):
        play = [{
            "name": "Evaluate extracted production HEC port predicates",
            "hosts": "localhost",
            "gather_facts": False,
            "vars": variables,
            "tasks": [{
                "name": "Assert production HEC port contract",
                "ansible.builtin.assert": {"that": predicates},
                "no_log": True,
            }],
        }]
        with tempfile.TemporaryDirectory(prefix="hec-port-contract-", dir="/tmp/opencode") as tmp:
            root = Path(tmp)
            playbook = root / "assert.yml"
            playbook.write_text(yaml.safe_dump(play, sort_keys=False), encoding="utf-8")
            env = os.environ.copy()
            env["ANSIBLE_LOCAL_TEMP"] = str(root / "local")
            env["ANSIBLE_REMOTE_TEMP"] = str(root / "remote")
            return subprocess.run(
                [str(ANSIBLE_PLAYBOOK), "-i", "localhost,", "--connection", "local", str(playbook)],
                env=env, capture_output=True, text=True, check=False,
            )

    def test_production_predicates_accept_only_bounded_integer_or_ascii_decimal(self):
        self.assertTrue(ANSIBLE_PLAYBOOK.is_file(),
                        f"missing explicitly supplied ansible-playbook: {ANSIBLE_PLAYBOOK}")
        self.assertTrue(self.predicates, "production preflight has no HEC port predicates")
        for value in VALID:
            with self.subTest(valid=repr(value)):
                result = self.evaluate_native(
                    {"splunk_server_hec_port": value}, self.predicates)
                self.assertEqual(result.returncode, 0,
                                 f"valid port {value!r} rejected:\n{result.stdout}\n{result.stderr}")
        for value in INVALID:
            with self.subTest(invalid=repr(value)):
                result = self.evaluate_native(
                    {"splunk_server_hec_port": value}, self.predicates)
                self.assertNotEqual(result.returncode, 0,
                                    f"invalid port {value!r} accepted")

    def test_every_downstream_port_consumer_uses_explicit_integer_normalization(self):
        consumers = []
        for path, tasks in ((PREFLIGHT_PATH, self.preflight), (HEC_TASKS_PATH, self.hec_tasks)):
            for task in tasks:
                text = task_text(task)
                if PORT_TOKEN.search(text) and module(task, "assert") is None:
                    consumers.append((path.name, task.get("name", "unnamed"), text))
        template = HEC_TEMPLATE_PATH.read_text(encoding="utf-8")
        consumers.append((HEC_TEMPLATE_PATH.name, "HEC listener rendering", template))
        self.assertTrue(consumers)
        missing = []
        for path, name, text in consumers:
            for occurrence in PORT_TOKEN.finditer(text):
                suffix = text[occurrence.end():]
                if re.match(r"\s*\|\s*int\b", suffix) is None:
                    missing.append(f"{path}: {name} at offset {occurrence.start()}")
        self.assertFalse(missing, "raw public HEC port reaches consumers: " + "; ".join(missing))

    def test_validation_endpoint_is_correlated_with_normalized_listener_port(self):
        endpoint_tasks = [task for task in self.preflight
                          if "splunk_server_hec_validation_endpoint" in task_text(task)]
        self.assertTrue(endpoint_tasks, "missing HEC validation endpoint contract")
        endpoint_text = "\n".join(task_text(task) for task in endpoint_tasks)
        self.assertRegex(endpoint_text, NORMALIZED_PORT,
                         "validation endpoint must target the normalized HEC listener port")

    def test_production_endpoint_predicates_reject_a_different_listener_port(self):
        self.assertTrue(self.endpoint_predicates,
                        "production preflight has no validation endpoint predicates")
        common = {
            "splunk_server_hec_port": "08088",
            "splunk_server_hec_ssl_enabled": True,
        }
        matching = self.evaluate_native(
            {**common, "splunk_server_hec_validation_endpoint":
             "https://127.0.0.1:8088/services/collector/event"},
            self.endpoint_predicates)
        self.assertEqual(matching.returncode, 0,
                         f"matching normalized endpoint rejected:\n{matching.stdout}\n{matching.stderr}")
        mismatched = self.evaluate_native(
            {**common, "splunk_server_hec_validation_endpoint":
             "https://127.0.0.1:8089/services/collector/event"},
            self.endpoint_predicates)
        self.assertNotEqual(mismatched.returncode, 0,
                            "endpoint using a different port was accepted")

    def test_production_endpoint_predicates_reject_malformed_authorities_and_suffixes(self):
        common = {
            "splunk_server_hec_port": "8088",
            "splunk_server_hec_ssl_enabled": True,
        }
        valid = (
            "https://splunk.example:8088/services/collector/event",
            "https://127.0.0.1:8088/services/collector/event",
            "https://[2001:db8::1]:8088/services/collector/event",
        )
        invalid = (
            "https://host?x:8088/services/collector/event",
            "https://host#x:8088/services/collector/event",
            "https://user@host:8088/services/collector/event",
            "https://ho st:8088/services/collector/event",
            "https://[:::]:8088/services/collector/event",
            "https://host/services/collector/event",
            "https://host:8088/services/collector/event?x=1",
            "https://host:8088/services/collector/event#fragment",
            "https://host:8088/services/collector/event\n",
        )
        for endpoint in valid:
            with self.subTest(valid_endpoint=endpoint):
                result = self.evaluate_native(
                    {**common, "splunk_server_hec_validation_endpoint": endpoint},
                    self.endpoint_predicates)
                self.assertEqual(result.returncode, 0,
                                 f"valid endpoint rejected: {endpoint!r}\n{result.stdout}\n{result.stderr}")
        for endpoint in invalid:
            with self.subTest(invalid_endpoint=repr(endpoint)):
                result = self.evaluate_native(
                    {**common, "splunk_server_hec_validation_endpoint": endpoint},
                    self.endpoint_predicates)
                self.assertNotEqual(result.returncode, 0,
                                    f"malformed endpoint accepted: {endpoint!r}")


if __name__ == "__main__":
    unittest.main()
