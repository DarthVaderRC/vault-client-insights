import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "vault-client-usage-analyzer"
    / "scripts"
    / "analyze_alias_namespace_presence.py"
)
SPEC = importlib.util.spec_from_file_location("analyze_alias_namespace_presence", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


FIELDNAMES = [
    "entity_id",
    "namespace_id",
    "alias_count",
    "alias_names",
    "alias_mount_paths",
    "alias_mount_types",
]


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


class AnalyzeAliasNamespacePresenceTests(unittest.TestCase):
    def test_load_namespace_map_preserves_root_empty_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "usage.json"
            json_path.write_text(
                json.dumps(
                    {
                        "data": {
                            "by_namespace": [
                                {"namespace_id": "root", "namespace_path": ""},
                                {"namespace_id": "ns1", "namespace_path": "apps/"},
                            ],
                            "months": [],
                        }
                    }
                ),
                encoding="utf-8",
            )

            namespace_map = MODULE.load_namespace_map(json_path)

            self.assertIn("root", namespace_map)
            self.assertEqual(namespace_map["root"], "")
            self.assertEqual(namespace_map["ns1"], "apps/")

    def test_group_alias_presence_keeps_root_mapped_not_unmapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "entities.csv"
            write_csv(
                csv_path,
                [
                    {
                        "entity_id": "e1",
                        "namespace_id": "root",
                        "alias_count": "1",
                        "alias_names": "shared@example.com",
                        "alias_mount_paths": "auth/jwt/gitlab/",
                        "alias_mount_types": "jwt",
                    },
                    {
                        "entity_id": "e2",
                        "namespace_id": "ns1",
                        "alias_count": "1",
                        "alias_names": "shared@example.com",
                        "alias_mount_paths": "auth/jwt/gitlab/",
                        "alias_mount_types": "jwt",
                    },
                ],
            )

            rows = MODULE.group_alias_presence(csv_path, {"root": "", "ns1": "apps/"}, min_namespaces=2)

            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(set(str(row["namespace_paths"]).split(";")), {"", "apps/"})
            self.assertEqual(set(str(row["namespace_pairs"]).split(";")), {"root:(root)", "ns1:apps/"})
            self.assertEqual(row["unmapped_namespace_ids"], "")

    def test_render_markdown_uses_generic_title(self) -> None:
        report = MODULE.render_markdown([], {"root": ""}, Path("entities.csv"), Path("usage.json"))

        self.assertIn("# Alias Namespace Presence", report)
        self.assertTrue(report.startswith("# Alias Namespace Presence\n"))


if __name__ == "__main__":
    unittest.main()
