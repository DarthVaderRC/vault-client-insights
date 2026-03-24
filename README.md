# Vault Client Usage Analyzer

A Claude skill and a set of standalone Python scripts for analyzing HashiCorp Vault client usage from two raw exports:

- the **counters activity JSON** from `sys/internal/counters/activity`
- an **identity entity inventory CSV** exported with the included script

They produce Markdown reports on client growth, namespace and auth-method distribution, entity inventory hygiene, and identities that are repeated across namespaces (a common driver of client counts).

The scripts use only the Python standard library (3.8+). The export script needs `bash`, `jq` and an authenticated `vault` CLI.

## Repository layout

```
vault-client-usage-analyzer/        The skill (this folder is what gets packaged)
  SKILL.md                          Instructions Claude follows when the skill triggers
  scripts/
    analyze_vault_utilization.py    Activity JSON -> usage and growth report
    analyze_vault_entities.py       Entity CSV (+ optional activity JSON) -> inventory report
    analyze_alias_namespace_presence.py  Entity CSV + activity JSON -> alias-in-many-namespaces list
    extract_entity_data.sh          Exports the entity CSV from a Vault cluster
tests/                              unittest suite; fixtures/ holds synthetic data only
tools/extract_jwt_oidc_aliases.sh   Ad hoc JWT/OIDC alias export (different CSV schema, not used by the analyzers)
build_skill.sh                      Runs the tests and builds dist/vault-client-usage-analyzer.skill
```

## Getting the inputs

Activity JSON (run against the root namespace; adjust the period to the billing window):

```bash
vault read -format=json sys/internal/counters/activity \
  start_time=2025-01-01T00:00:00Z end_time=2025-12-31T23:59:59Z > activity.json
```

Entity CSV (walks root and every nested namespace; one `vault read` per entity, so large clusters take a while):

```bash
./vault-client-usage-analyzer/scripts/extract_entity_data.sh entities.csv
```

The token needs `list` on `sys/namespaces` and `identity/entity/id`, and `read` on `identity/entity/id/*`, in every namespace.

## Running the analyzers directly

```bash
python3 vault-client-usage-analyzer/scripts/analyze_vault_utilization.py activity.json -o usage-report.md
```

```bash
python3 vault-client-usage-analyzer/scripts/analyze_vault_entities.py entities.csv --usage-json activity.json -o entity-analysis.md
```

```bash
python3 vault-client-usage-analyzer/scripts/analyze_alias_namespace_presence.py entities.csv activity.json --csv-out alias-namespace-presence.csv --md-out alias-namespace-presence.md
```

Each script has `--help`. [SKILL.md](vault-client-usage-analyzer/SKILL.md) covers every option and how to interpret the results, including the caveats (entities are not the same as clients, `last_update_time` is not a last-login time, and so on).

## Using it as a Claude skill

Build the package:

```bash
./build_skill.sh
```

Then do one of the following:

- **Claude Code:** copy the `vault-client-usage-analyzer/` folder to `~/.claude/skills/` (personal) or `.claude/skills/` in a project.
- **Claude.ai / Claude Desktop:** upload `dist/vault-client-usage-analyzer.skill` under Settings > Capabilities > Skills.

Then ask something like "Analyze this Vault activity export and entity CSV" with the files attached or in the working directory.

## Running the tests

```bash
python3 -m unittest discover -s tests
```

The end-to-end tests run every script as a CLI against `tests/fixtures/`, including the export script against a stub `vault` binary (skipped if `jq` is not installed).

## Handling customer data

Exports and reports contain customer namespace names and, in several outputs, **unredacted alias names that are often email addresses**. Keep them out of this repository:

- `private/` is git-ignored as a local working area for engagement data. Keep exports and reports there and never commit from it.
- Test fixtures must stay synthetic. Never copy a real export into `tests/`.
