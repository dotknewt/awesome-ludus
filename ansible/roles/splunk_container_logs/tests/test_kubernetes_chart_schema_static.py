"""Static regressions for the pinned chart's logs-only pipeline overrides.

Production regressions detected: reintroducing the all-false
``splunkObservability`` override or emitting null disabled-pipeline entries in
the rendered-values template.
"""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).parents[1]
TEMPLATE = ROLE / "templates" / "kubernetes-values.yaml.j2"
ARTIFACTS = ROLE / "vars" / "artifacts.yml"


class KubernetesChartSchemaStatic(unittest.TestCase):
    def test_logs_only_values_omit_disabled_pipeline_entries(self):
        template = TEMPLATE.read_text(encoding="utf-8")
        artifacts = yaml.safe_load(ARTIFACTS.read_text(encoding="utf-8"))
        required_values = artifacts["splunk_container_logs_artifacts"]["chart"][
            "required_logs_only_values"
        ]

        self.assertNotIn("splunkObservability:", template)
        self.assertNotIn("splunkObservability", required_values)
        self.assertNotIn("realm:", template)

        self.assertIn("logsEnabled: true", template)
        self.assertIn("metricsEnabled: false", template)
        self.assertIn("tracesEnabled: false", template)
        platform_values = required_values["splunkPlatform"]
        self.assertEqual(platform_values["logsEnabled"], True)
        self.assertEqual(platform_values["metricsEnabled"], False)
        self.assertEqual(platform_values["tracesEnabled"], False)

        self.assertIn("secret:\n  create: false", template)
        self.assertEqual(required_values["secret"]["create"], False)
        self.assertIn("noDropLogsPipeline: false", template)
        self.assertIn("logs:\n          receivers: [file_log]", template)
        self.assertNotIn("metrics: null", template)
        self.assertNotIn("traces: null", template)
        for port in ("otlp", "otlp-http", "zipkin", "jaeger-thrift",
                     "jaeger-grpc", "opampforwarder"):
            self.assertIn(f"{port}: null", template)


if __name__ == "__main__":
    unittest.main()
