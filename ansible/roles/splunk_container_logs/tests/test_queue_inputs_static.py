"""Source-only contracts for strict queue numeric filters and consumers."""

import ast
from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).parents[1]
FILTER = ROLE / "filter_plugins" / "queue_inputs.py"


def function_nodes(tree):
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class QueueInputsStatic(unittest.TestCase):
    def test_strict_shared_parser_has_type_grammar_size_and_bounds_guards(self):
        source = FILTER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        functions = function_nodes(tree)
        parser = functions["_parse_bounded_decimal"]
        calls = [node for node in ast.walk(parser) if isinstance(node, ast.Call)]

        isinstance_calls = [
            node for node in calls
            if call_name(node.func) == "isinstance" and len(node.args) == 2
            and isinstance(node.args[0], ast.Name) and node.args[0].id == "value"
        ]
        type_guards = {
            ast.unparse(node.args[1]): node.lineno
            for node in isinstance_calls
            if isinstance(node.args[1], ast.Name)
        }
        self.assertIn("bool", type_guards)
        self.assertIn("int", type_guards)
        self.assertIn("str", type_guards)
        self.assertLess(type_guards["bool"], type_guards["int"])

        regex_calls = [
            node for node in calls
            if call_name(node.func) == "fullmatch"
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
        ]
        self.assertEqual(len(regex_calls), 1)
        regex = regex_calls[0]
        self.assertEqual(ast.literal_eval(regex.args[0]), r"(?:0|[1-9][0-9]*)")
        self.assertIn("ASCII", ast.unparse(regex))
        self.assertIn("value", ast.unparse(regex))
        regex_flags = next((keyword.value for keyword in regex.keywords if keyword.arg == "flags"), None)
        self.assertIsNotNone(regex_flags)
        self.assertEqual(ast.unparse(regex_flags), "re.ASCII")

        conversions = [node for node in calls if call_name(node.func) == "int"]
        plain_integer_conversion = next(
            node for node in conversions
            if len(node.args) == 1 and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "value"
        )
        self.assertTrue(plain_integer_conversion)
        string_conversion = next(
            node for node in conversions
            if len(node.args) == 2 and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "value"
        )
        self.assertEqual(ast.literal_eval(string_conversion.args[1]), 10)
        length_guards = [
            node for node in ast.walk(parser)
            if isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Call)
            and call_name(node.left.func) == "len"
            and node.left.args and isinstance(node.left.args[0], ast.Name)
            and node.left.args[0].id == "value"
        ]
        self.assertTrue(length_guards, "string length must be bounded before decimal conversion")
        self.assertLess(max(node.lineno for node in length_guards), string_conversion.lineno)
        max_digits = next(
            node.value for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "MAX_DECIMAL_DIGITS"
                    for target in node.targets)
        )
        self.assertEqual(ast.literal_eval(max_digits), 13)
        self.assertTrue(any(
            isinstance(node, ast.Compare)
            and any(isinstance(item, ast.Name) and item.id in {"minimum", "maximum"}
                    for item in (node.left, *node.comparators))
            and any(isinstance(op, (ast.Lt, ast.Gt)) for op in node.ops)
            for node in ast.walk(parser)
        ), "configured numeric bounds must be enforced")

        errors = [node for node in calls if call_name(node.func) == "AnsibleFilterError"]
        self.assertTrue(errors)
        fixed_errors = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"TYPE_ERROR", "FORMAT_ERROR", "BOUNDS_ERROR"}
        }
        self.assertEqual(set(fixed_errors), {"TYPE_ERROR", "FORMAT_ERROR", "BOUNDS_ERROR"})
        for error in errors:
            self.assertTrue(error.args and isinstance(error.args[0], ast.Name)
                            and error.args[0].id in fixed_errors)
            self.assertEqual(len(error.args), 1)
            self.assertFalse(error.keywords)
        self.assertNotIn("str(exc)", source)
        self.assertNotIn("repr(exc)", source)
        self.assertNotIn("f\"", source)

    def test_public_filters_are_registered_with_exact_bounds(self):
        tree = ast.parse(FILTER.read_text(encoding="utf-8"))
        functions = function_nodes(tree)
        self.assertIn("_parse_bounded_decimal", functions)
        filter_class = next(node for node in tree.body
                            if isinstance(node, ast.ClassDef) and node.name == "FilterModule")
        filters = next(node for node in filter_class.body
                       if isinstance(node, ast.FunctionDef) and node.name == "filters")
        returned = next(node for node in ast.walk(filters) if isinstance(node, ast.Return))
        self.assertIsInstance(returned.value, ast.Dict)
        registration = {
            ast.literal_eval(key): value
            for key, value in zip(returned.value.keys, returned.value.values)
        }
        self.assertEqual(set(registration), {
            "splunk_container_queue_size", "splunk_container_queue_disk_mib",
        })
        self.assertEqual(ast.unparse(registration["splunk_container_queue_size"]), "self.queue_size")
        self.assertEqual(ast.unparse(registration["splunk_container_queue_disk_mib"]), "self.queue_disk_mib")

        expected_bounds = {
            "queue_size": (1, 2147483647),
            "queue_disk_mib": (200, 8796093022207),
        }
        for method_name, bounds in expected_bounds.items():
            method = functions[method_name]
            parser_call = next(
                node for node in ast.walk(method)
                if isinstance(node, ast.Call) and call_name(node.func) == "_parse_bounded_decimal"
            )
            self.assertEqual(tuple(ast.literal_eval(arg) for arg in parser_call.args[1:3]), bounds)

    def test_preflight_and_all_template_consumers_use_strict_filter_results(self):
        preflight = yaml.safe_load((ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8"))
        wrapper = next(task for task in preflight
                       if task.get("name") == "Validate shared HEC transport and bounded queue inputs")
        assertion = wrapper["block"][0]["ansible.builtin.assert"]["that"]
        normalized = [" ".join(value.split()) for value in assertion]
        self.assertIn("(splunk_container_logs_queue_size | splunk_container_queue_size) is integer", normalized)
        self.assertIn("(splunk_container_logs_queue_max_disk_mib | splunk_container_queue_disk_mib) is integer", normalized)
        self.assertEqual(len(assertion), 23)

        docker = (ROLE / "templates" / "docker-otel.yaml.j2").read_text(encoding="utf-8")
        kube = (ROLE / "templates" / "kubernetes-values.yaml.j2").read_text(encoding="utf-8")
        expected = (
            (docker, "max_size: {{ (splunk_container_logs_queue_max_disk_mib | splunk_container_queue_disk_mib) * 1048576 }}"),
            (docker, "queue_size: {{ splunk_container_logs_queue_size | splunk_container_queue_size }}"),
            (kube, "queueSize: {{ splunk_container_logs_queue_size | splunk_container_queue_size }}"),
            (kube, "max_size: {{ (splunk_container_logs_queue_max_disk_mib | splunk_container_queue_disk_mib) * 1048576 }}"),
            (kube, "queue_size: {{ splunk_container_logs_queue_size | splunk_container_queue_size }}"),
        )
        for source, snippet in expected:
            self.assertIn(snippet, source)
        self.assertEqual(sum(source.count(snippet) for source, snippet in expected), 5)
        self.assertNotIn("splunk_container_logs_queue_size | int", docker + kube)
        self.assertNotIn("max_size: {{ splunk_container_logs_queue_max_disk_mib *", docker + kube)


if __name__ == "__main__":
    unittest.main()
