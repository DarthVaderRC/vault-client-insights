"""Run each analyzer and the extract script as a user would, against synthetic fixtures."""

import csv
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "vault-client-usage-analyzer" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


class CLIEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_utilization_cli(self) -> None:
        out = self.tmp / "nested" / "usage-report.md"
        result = run(sys.executable, str(SCRIPTS / "analyze_vault_utilization.py"), str(FIXTURES / "activity.json"), "-o", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("# Vault Client Utilization Analysis", out.read_text(encoding="utf-8"))

    def test_entities_cli_with_all_artifacts(self) -> None:
        result = run(
            sys.executable, str(SCRIPTS / "analyze_vault_entities.py"), str(FIXTURES / "entities.csv"),
            "--usage-json", str(FIXTURES / "activity.json"),
            "-o", str(self.tmp / "entity-analysis.md"),
            "--sqlite-out", str(self.tmp / "entities.sqlite"),
            "--summary-json", str(self.tmp / "summary.json"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.tmp / "entity-analysis.md").read_text(encoding="utf-8")
        self.assertIn("Monthly Growth Comparison", report)
        self.assertTrue((self.tmp / "entities.sqlite").exists())
        self.assertTrue((self.tmp / "summary.json").exists())

    def test_entities_cli_rejects_bad_window(self) -> None:
        result = run(sys.executable, str(SCRIPTS / "analyze_vault_entities.py"), str(FIXTURES / "entities.csv"), "--window-start", "2025-6")
        self.assertEqual(result.returncode, 1)
        self.assertIn("YYYY-MM", result.stderr)

    def test_alias_presence_cli(self) -> None:
        csv_out = self.tmp / "alias.csv"
        result = run(
            sys.executable, str(SCRIPTS / "analyze_alias_namespace_presence.py"),
            str(FIXTURES / "entities.csv"), str(FIXTURES / "activity.json"),
            "--csv-out", str(csv_out), "--md-out", str(self.tmp / "alias.md"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = {(r["alias_name"], r["alias_mount_path"]): r for r in csv.DictReader(csv_out.read_text(encoding="utf-8").splitlines())}
        alice = rows[("alice@example.com", "auth/oidc/")]
        self.assertEqual(alice["distinct_namespace_count"], "3")
        self.assertEqual(set(alice["namespace_paths"].split(";")), {"", "team-a/", "team-b/"})
        self.assertIn("upper bound", (self.tmp / "alias.md").read_text(encoding="utf-8"))

    @unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "needs bash and jq")
    def test_extract_script_walks_nested_namespaces_and_quotes_csv(self) -> None:
        stub_dir = self.tmp / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "vault"
        stub.write_text(textwrap.dedent("""\
            #!/bin/bash
            ns=""; for a in "$@"; do case $a in -namespace=*) ns=${a#-namespace=};; esac; done
            last="${@: -1}"
            case "$1" in
              token) exit 0;;
              list)
                case "$ns|$last" in
                  "|sys/namespaces") echo '["team-a/"]';;
                  "team-a/|sys/namespaces") echo '["child/"]';;
                  "|identity/entity/id") echo '["e-root"]';;
                  "team-a/child/|identity/entity/id") echo '["e-child"]';;
                  *) exit 2;;
                esac;;
              read)
                id=${last##*/}
                if [ "$id" = e-root ]; then
                  echo '{"data":{"id":"e-root","name":"n1","namespace_id":"root","creation_time":"2025-07-01T00:00:00Z","last_update_time":"2025-07-01T00:00:00Z","disabled":false,"metadata":{"team":"a,b","note":"say \\"hi\\""},"aliases":[{"id":"a1","name":"bob@x.com","mount_path":"auth/oidc/","mount_type":"oidc"}]}}'
                else
                  echo '{"data":{"id":"e-child","name":"n2","namespace_id":"Cc333","creation_time":"2025-07-02T00:00:00Z","last_update_time":"2025-07-02T00:00:00Z","disabled":false,"metadata":null,"aliases":[]}}'
                fi;;
            esac
            """))
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        out = self.tmp / "entities.csv"
        env = dict(os.environ, PATH=f"{stub_dir}{os.pathsep}{os.environ['PATH']}")
        result = run("bash", str(SCRIPTS / "extract_entity_data.sh"), str(out), env=env)
        self.assertEqual(result.returncode, 0, result.stderr)

        rows = list(csv.DictReader(out.read_text(encoding="utf-8").splitlines()))
        self.assertEqual([r["entity_id"] for r in rows], ["e-root", "e-child"])
        self.assertEqual(rows[0]["metadata"], '{"team":"a,b","note":"say \\"hi\\""}')
        self.assertEqual(rows[0]["disabled"], "false")
        self.assertEqual(rows[1]["alias_count"], "0")

        analyze = run(sys.executable, str(SCRIPTS / "analyze_vault_entities.py"), str(out))
        self.assertEqual(analyze.returncode, 0, analyze.stderr)


if __name__ == "__main__":
    unittest.main()
