import importlib.util
import json
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "vault-client-usage-analyzer"
    / "scripts"
    / "analyze_vault_utilization.py"
)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SPEC = importlib.util.spec_from_file_location("analyze_vault_utilization", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def base_payload() -> dict:
    return {
        "data": {
            "start_time": "2025-09-01T00:00:00Z",
            "end_time": "2025-10-31T23:59:59Z",
            "total": {
                "clients": 0,
                "entity_clients": 0,
                "non_entity_clients": 0,
                "acme_clients": 0,
                "secret_syncs": 0,
                "distinct_entities": 0,
                "non_entity_tokens": 0,
            },
            "by_namespace": [],
            "months": [],
        }
    }


class AnalyzeVaultUtilizationTests(unittest.TestCase):
    def test_custom_auth_mounts_are_grouped_by_backend_type(self) -> None:
        payload = base_payload()
        payload["data"]["total"]["clients"] = 11
        payload["data"]["total"]["entity_clients"] = 11
        payload["data"]["by_namespace"] = [
            {
                "namespace_id": "ns1",
                "namespace_path": "payments/",
                "counts": {
                    "clients": 11,
                    "entity_clients": 11,
                    "non_entity_clients": 0,
                    "secret_syncs": 0,
                },
                "mounts": [
                    {
                        "mount_path": "auth/kubernetes-dc1-prod/",
                        "counts": {"clients": 6, "entity_clients": 6},
                    },
                    {
                        "mount_path": "auth/kubernetes-dc2-prod/",
                        "counts": {"clients": 4, "entity_clients": 4},
                    },
                    {
                        "mount_path": "auth/ldap/",
                        "counts": {"clients": 1, "entity_clients": 1},
                    },
                ],
            }
        ]

        summary = MODULE.analyze(payload, top_namespaces=10, top_mounts=10, top_growth=10)
        auth = dict(summary["auth_methods"])

        self.assertEqual(MODULE.get_auth_type({"mount_path": "auth/kubernetes-dc1-prod/"}), "kubernetes")
        self.assertEqual(auth["kubernetes"]["clients"], 10)
        self.assertEqual(auth["ldap"]["clients"], 1)
        self.assertEqual(summary["auth_methods"][0][0], "kubernetes")

    def test_masked_fallback_preserves_root_namespace_growth(self) -> None:
        payload = base_payload()
        payload["data"]["start_time"] = "2025-06-01T00:00:00Z"
        payload["data"]["end_time"] = "2025-08-31T23:59:59Z"
        payload["data"]["total"]["clients"] = 3
        payload["data"]["total"]["entity_clients"] = 3
        payload["data"]["by_namespace"] = [
            {
                "namespace_id": "masked",
                "namespace_path": "ns-XXX-XX-XXXX",
                "counts": {"clients": 3, "entity_clients": 3, "non_entity_clients": 0, "secret_syncs": 0},
                "mounts": [],
            }
        ]
        payload["data"]["months"] = [
            {
                "timestamp": "2025-06-30T23:59:59Z",
                "new_clients": {
                    "counts": {"clients": 2, "entity_clients": 2, "non_entity_clients": 0, "secret_syncs": 0},
                    "namespaces": [
                        {
                            "namespace_id": "root-id",
                            "namespace_path": "",
                            "counts": {"clients": 2, "entity_clients": 2, "non_entity_clients": 0, "secret_syncs": 0},
                            "mounts": [],
                        }
                    ],
                },
                "namespaces": [{"namespace_id": "root-id", "namespace_path": ""}],
            },
            {
                "timestamp": "2025-08-31T23:59:59Z",
                "new_clients": {
                    "counts": {"clients": 1, "entity_clients": 1, "non_entity_clients": 0, "secret_syncs": 0},
                    "namespaces": [
                        {
                            "namespace_id": "team-id",
                            "namespace_path": "team-a/",
                            "counts": {"clients": 1, "entity_clients": 1, "non_entity_clients": 0, "secret_syncs": 0},
                            "mounts": [],
                        }
                    ],
                },
                "namespaces": [{"namespace_id": "team-id", "namespace_path": "team-a/"}],
            },
        ]

        summary = MODULE.analyze(payload, top_namespaces=10, top_mounts=10, top_growth=10)

        self.assertEqual(summary["period"]["namespaces"], 2)
        self.assertEqual(sum(ns["clients"] for ns in summary["all_namespaces"]), 3)
        self.assertTrue(any(ns["path"] == "" and ns["clients"] == 2 for ns in summary["all_namespaces"]))
        self.assertEqual(summary["top_growth"][0], ("", 2))

    def test_complete_last_month_is_not_marked_partial(self) -> None:
        payload = base_payload()
        payload["data"]["total"]["clients"] = 120
        payload["data"]["total"]["entity_clients"] = 120
        payload["data"]["months"] = [
            {
                "timestamp": "2025-09-30T23:59:59Z",
                "new_clients": {
                    "counts": {"clients": 100, "entity_clients": 100, "non_entity_clients": 0, "secret_syncs": 0},
                    "namespaces": [],
                },
                "namespaces": [],
            },
            {
                "timestamp": "2025-10-31T23:59:59Z",
                "new_clients": {
                    "counts": {"clients": 20, "entity_clients": 20, "non_entity_clients": 0, "secret_syncs": 0},
                    "namespaces": [],
                },
                "namespaces": [],
            },
        ]

        summary = MODULE.analyze(payload, top_namespaces=10, top_mounts=10, top_growth=10)
        report = MODULE.render_markdown(summary)

        self.assertFalse(summary["last_month_partial"])
        self.assertNotIn("(partial)", report)
        self.assertNotIn("likely partial month data", report)

    def test_truncated_last_month_is_marked_partial(self) -> None:
        payload = base_payload()
        payload["data"]["end_time"] = "2025-10-15T12:00:00Z"
        payload["data"]["total"]["clients"] = 120
        payload["data"]["total"]["entity_clients"] = 120
        payload["data"]["months"] = [
            {
                "timestamp": "2025-09-30T23:59:59Z",
                "new_clients": {
                    "counts": {"clients": 100, "entity_clients": 100, "non_entity_clients": 0, "secret_syncs": 0},
                    "namespaces": [],
                },
                "namespaces": [],
            },
            {
                "timestamp": "2025-10-31T23:59:59Z",
                "new_clients": {
                    "counts": {"clients": 20, "entity_clients": 20, "non_entity_clients": 0, "secret_syncs": 0},
                    "namespaces": [],
                },
                "namespaces": [],
            },
        ]

        summary = MODULE.analyze(payload, top_namespaces=10, top_mounts=10, top_growth=10)

        self.assertTrue(summary["last_month_partial"])

    def test_report_renders_mount_and_growth_tables_with_neutral_insights(self) -> None:
        payload = json.loads((FIXTURES / "activity.json").read_text(encoding="utf-8"))
        summary = MODULE.analyze(payload, top_namespaces=10, top_mounts=5, top_growth=3)
        report = MODULE.render_markdown(summary)

        self.assertIn("Mounts by Client Count", report)
        self.assertIn("`auth/oidc/`", report)
        self.assertIn("Namespaces by New Clients", report)
        self.assertIn("Key Insights & Discussion Points", report)
        self.assertNotIn("zero-trust", report)
        self.assertNotIn("Opportunity:", report)
        self.assertNotIn("Plan for", report)
        self.assertIn("simple run-rate, not a forecast", report)

    def test_auth_usage_note_depends_on_method(self) -> None:
        self.assertIn("workloads", MODULE.auth_usage_note("kubernetes")[0])
        self.assertIn("people", MODULE.auth_usage_note("ldap")[0])
        self.assertIn("tokens", MODULE.auth_usage_note("token")[0])

    def test_growth_trend_labels(self) -> None:
        def months(*values):
            return [{"clients": v} for v in values]

        self.assertEqual(MODULE.growth_trend(months(10, 10, 30, 30))[0], "accelerating")
        self.assertEqual(MODULE.growth_trend(months(30, 30, 10, 10))[0], "slowing")
        self.assertEqual(MODULE.growth_trend(months(10, 11, 10, 11))[0], "steady")
        self.assertIsNone(MODULE.growth_trend(months(1, 2)))


if __name__ == "__main__":
    unittest.main()
