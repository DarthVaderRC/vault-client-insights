import csv
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "vault-client-usage-analyzer"
    / "scripts"
    / "analyze_vault_entities.py"
)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SPEC = importlib.util.spec_from_file_location("analyze_vault_entities", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


FIELDNAMES = [
    "entity_id",
    "name",
    "namespace_id",
    "creation_time",
    "last_update_time",
    "alias_count",
    "alias_id",
    "alias_names",
    "alias_mount_paths",
    "alias_mount_types",
    "disabled",
    "metadata",
]


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


class AnalyzeVaultEntitiesTests(unittest.TestCase):
    def test_normalize_window_rejects_invalid_formats_and_reversed_ranges(self) -> None:
        with self.assertRaisesRegex(MODULE.CLIError, "--window-start must be in YYYY-MM format"):
            MODULE.normalize_window("2025-6", "2026-02")

        with self.assertRaisesRegex(MODULE.CLIError, "--window-start must be earlier than or equal to --window-end"):
            MODULE.normalize_window("2026-02", "2025-06")

    def test_mount_specific_alias_metrics_use_membership_not_exact_set_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "entities.csv"
            write_csv(
                csv_path,
                [
                    {
                        "entity_id": "e1",
                        "name": "entity_1",
                        "namespace_id": "ns-a",
                        "creation_time": "2025-06-01T00:00:00.000000000Z",
                        "last_update_time": "2025-06-01T00:00:00.000000000Z",
                        "alias_count": "2",
                        "alias_id": "a1;a2",
                        "alias_names": "alice@example.com;alice@example.com",
                        "alias_mount_paths": "auth/jwt/gitlab/;auth/jwt/admin/",
                        "alias_mount_types": "jwt;jwt",
                        "disabled": "false",
                        "metadata": "null",
                    },
                    {
                        "entity_id": "e2",
                        "name": "entity_2",
                        "namespace_id": "ns-b",
                        "creation_time": "2025-06-02T00:00:00.000000000Z",
                        "last_update_time": "2025-06-02T00:00:00.000000000Z",
                        "alias_count": "1",
                        "alias_id": "a3",
                        "alias_names": "alice@example.com",
                        "alias_mount_paths": "auth/jwt/gitlab/",
                        "alias_mount_types": "jwt",
                        "disabled": "false",
                        "metadata": "null",
                    },
                    {
                        "entity_id": "e3",
                        "name": "entity_3",
                        "namespace_id": "ns-c",
                        "creation_time": "2025-06-03T00:00:00.000000000Z",
                        "last_update_time": "2025-06-03T00:00:00.000000000Z",
                        "alias_count": "2",
                        "alias_id": "a4;a5",
                        "alias_names": "oidc-user;oidc-user",
                        "alias_mount_paths": "auth/oidc/;auth/jwt/admin/",
                        "alias_mount_types": "oidc;jwt",
                        "disabled": "false",
                        "metadata": "null",
                    },
                    {
                        "entity_id": "e4",
                        "name": "entity_4",
                        "namespace_id": "ns-d",
                        "creation_time": "2025-06-04T00:00:00.000000000Z",
                        "last_update_time": "2025-06-04T00:00:00.000000000Z",
                        "alias_count": "1",
                        "alias_id": "a6",
                        "alias_names": "oidc-user",
                        "alias_mount_paths": "auth/oidc/",
                        "alias_mount_types": "oidc",
                        "disabled": "false",
                        "metadata": "null",
                    },
                ],
            )

            analysis = MODULE.analyze(
                csv_path=csv_path,
                utilization_report=None,
                window_start="2025-06",
                window_end="2025-06",
                top_namespaces=10,
                top_aliases=10,
            )

            spread = {item["mount_path"]: item for item in analysis["mount_alias_spread"]}
            self.assertEqual(spread["auth/jwt/gitlab/"]["distinct_email_aliases"], 1)
            self.assertEqual(spread["auth/jwt/gitlab/"]["multi_namespace_aliases"], 1)
            self.assertEqual(spread["auth/oidc/"]["multi_namespace_aliases"], 1)
            # admin mount aliases also spread, because membership (not exact mount set) is used
            self.assertEqual(spread["auth/jwt/admin/"]["multi_namespace_aliases"], 2)

    def test_write_sqlite_preserves_duplicate_entity_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "entities.csv"
            sqlite_path = Path(tmpdir) / "entities.sqlite"
            write_csv(
                csv_path,
                [
                    {
                        "entity_id": "dup-entity",
                        "name": "entity_dup_1",
                        "namespace_id": "ns-a",
                        "creation_time": "2025-06-01T00:00:00.000000000Z",
                        "last_update_time": "2025-06-01T00:00:00.000000000Z",
                        "alias_count": "1",
                        "alias_id": "a1",
                        "alias_names": "dup@example.com",
                        "alias_mount_paths": "auth/jwt/gitlab/",
                        "alias_mount_types": "jwt",
                        "disabled": "false",
                        "metadata": "null",
                    },
                    {
                        "entity_id": "dup-entity",
                        "name": "entity_dup_2",
                        "namespace_id": "ns-b",
                        "creation_time": "2025-06-02T00:00:00.000000000Z",
                        "last_update_time": "2025-06-02T00:00:00.000000000Z",
                        "alias_count": "1",
                        "alias_id": "a2",
                        "alias_names": "dup@example.com",
                        "alias_mount_paths": "auth/jwt/gitlab/",
                        "alias_mount_types": "jwt",
                        "disabled": "false",
                        "metadata": "null",
                    },
                ],
            )

            analysis = MODULE.analyze(
                csv_path=csv_path,
                utilization_report=None,
                window_start="2025-06",
                window_end="2025-06",
                top_namespaces=10,
                top_aliases=10,
            )
            MODULE.write_sqlite(sqlite_path, analysis)

            with sqlite3.connect(sqlite_path) as conn:
                stored_rows = conn.execute(
                    "SELECT COUNT(*) FROM entities WHERE entity_id = ?",
                    ("dup-entity",),
                ).fetchone()[0]

            self.assertEqual(analysis["duplicate_metrics"]["exact_duplicate_entity_ids"], 1)
            self.assertEqual(stored_rows, 2)

    def test_parse_ts_accepts_vault_rfc3339_variants(self) -> None:
        self.assertEqual(MODULE.parse_ts("2025-07-01T00:00:00Z").isoformat(), "2025-07-01T00:00:00+00:00")
        self.assertEqual(MODULE.parse_ts("2025-07-01T00:00:00.123456789Z").microsecond, 123456)
        self.assertEqual(MODULE.parse_ts("2025-07-01T10:00:00+10:00").hour, 0)
        self.assertIsNone(MODULE.parse_ts("null"))
        with self.assertRaises(ValueError):
            MODULE.parse_ts("01/07/2025")

    def test_window_defaults_to_data_and_usage_json(self) -> None:
        csv_only = MODULE.analyze(FIXTURES / "entities.csv", None, None, None, 10, 10)
        self.assertEqual((csv_only["window_start"], csv_only["window_end"]), ("2025-05", "2025-09"))

        with_usage = MODULE.analyze(
            FIXTURES / "entities.csv", None, None, None, 10, 10, usage_json=FIXTURES / "activity.json"
        )
        self.assertEqual((with_usage["window_start"], with_usage["window_end"]), ("2025-06", "2025-08"))
        self.assertEqual(with_usage["pre_window_count"], 1)
        self.assertEqual(with_usage["post_window_count"], 1)
        self.assertEqual(with_usage["first_post_window_month"], "2025-09")

    def test_usage_json_resolves_namespace_names_and_monthly_clients(self) -> None:
        analysis = MODULE.analyze(
            FIXTURES / "entities.csv", None, None, None, 10, 10, usage_json=FIXTURES / "activity.json"
        )
        names = [item["namespace"] for item in analysis["top_creation_namespaces_window"]]
        self.assertIn("team-a/ (Aa111)", names)
        june = next(row for row in analysis["monthly_comparison"] if row["month"] == "2025-06")
        self.assertEqual(june["report_new_clients"], 2)

    def test_report_is_generic_and_last_update_text_matches_data(self) -> None:
        analysis = MODULE.analyze(FIXTURES / "entities.csv", None, None, None, 10, 10)
        report = MODULE.render_report(analysis, "Report")
        self.assertNotIn("gitlab", report.lower())
        self.assertNotIn("creation-time inventory", report)
        self.assertIn("modified after creation", report)
        self.assertIn("`auth/oidc/`", report)
        self.assertNotIn("alice@example.com", report)

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "entities.csv"
            row = {name: "" for name in FIELDNAMES}
            row.update(
                entity_id="e1", name="n1", namespace_id="root", alias_count="0", disabled="false",
                creation_time="2025-06-01T00:00:00Z", last_update_time="2025-06-01T00:00:00Z", metadata="null",
            )
            write_csv(csv_path, [row])
            static = MODULE.render_report(MODULE.analyze(csv_path, None, None, None, 10, 10), "Report")
        self.assertIn("creation-time inventory", static)


if __name__ == "__main__":
    unittest.main()
