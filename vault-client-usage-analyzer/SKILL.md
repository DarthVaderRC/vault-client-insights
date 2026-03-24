---
name: vault-client-usage-analyzer
description: Analyze HashiCorp Vault client usage from raw exports. Use when the user has a Vault counters activity JSON (`sys/internal/counters/activity`) and/or an identity entity inventory CSV and wants client growth and distribution, top namespaces and auth methods, entity inventory and hygiene checks, or a list of aliases that exist in multiple namespaces (and the client count that implies). Produces Markdown reports, plus CSV, SQLite or JSON artifacts where useful.
---

# Vault Client Usage Analyzer

Three stdlib-only Python 3.8+ analyzers plus one export script, all in `scripts/` next to this file. Run them with the skill directory's absolute path (for example `python3 <skill-dir>/scripts/analyze_vault_utilization.py ...`), not a path relative to the user's working directory.

## Inputs

| Input | What it is | How to get it |
|-------|------------|---------------|
| Counters activity JSON | Client counts for a billing period, by namespace, mount and month | `vault read -format=json sys/internal/counters/activity start_time=2025-01-01T00:00:00Z end_time=2025-12-31T23:59:59Z > activity.json` (run in the root namespace with a token that can read it) |
| Entity inventory CSV | One row per identity entity, aliases joined with `;` | `scripts/extract_entity_data.sh entities.csv` (walks root and all nested namespaces; needs `vault` and `jq`) |

The entity CSV columns are `entity_id, name, namespace_id, creation_time, last_update_time, alias_count, alias_id, alias_names, alias_mount_paths, alias_mount_types, disabled, metadata`. The analyzers reject a CSV that lacks them. If the user has a CSV in another shape, map it to these columns first instead of editing the analyzers.

Customer exports are sometimes masked: top-level `data.by_namespace[].namespace_path` replaced with values like `ns-XXX-...`. Both the utilization and alias analyzers detect this and fall back to the real paths in `data.months[].namespaces[]` and `data.months[].new_clients.namespaces[]`.

## Pick the analyzer

| User wants | Script | Inputs |
|------------|--------|--------|
| Overall client totals, growth by month, top namespaces, auth methods, mounts, secret sync | `analyze_vault_utilization.py` | activity JSON |
| Entity inventory: creation trends, which namespaces and mounts drive growth, identities repeated across namespaces, duplicates | `analyze_vault_entities.py` | entity CSV, optionally `--usage-json` |
| Full list of each `alias_name + mount_path` that exists in 2+ namespaces, with namespace paths | `analyze_alias_namespace_presence.py` | entity CSV and activity JSON |

When the user has both inputs and asks a broad question ("what's going on with our Vault usage?"), run the utilization analyzer first, then the entity analyzer with `--usage-json`.

### Usage and growth

```bash
python3 scripts/analyze_vault_utilization.py activity.json -o usage-report.md \
  [--top-namespaces 20] [--top-mounts 30] [--top-growth 20]
```

- Auth-method totals are per backend type: custom mount paths such as `auth/kubernetes-prod/` are grouped under `kubernetes`.
- The last month is flagged as partial only when `data.end_time` falls before that month's end.
- The "Key Insights & Discussion Points" section is rule-based. Treat it as a starting point and check it against the tables before repeating it to the user.

### Entity inventory

```bash
python3 scripts/analyze_vault_entities.py entities.csv -o entity-analysis.md \
  [--usage-json activity.json] [--window-start YYYY-MM --window-end YYYY-MM] \
  [--sqlite-out entities.sqlite] [--summary-json summary.json] [--title "..."]
```

- `--usage-json` (preferred) resolves namespace IDs to paths and adds a month-by-month comparison of new clients against entities created. `--utilization-report usage-report.md` is the older alternative and only maps the namespaces listed in that report.
- The window defaults to the activity JSON's months, or else the CSV's creation span. Pass `--window-start`/`--window-end` when the user names a billing period.
- `--sqlite-out` is for follow-up questions: tables `entities` (one row per CSV row, duplicates kept) and `aliases`. Query it with `sqlite3` instead of re-parsing the CSV.

### Alias namespace presence

```bash
python3 scripts/analyze_alias_namespace_presence.py entities.csv activity.json \
  --csv-out alias-namespace-presence.csv --md-out alias-namespace-presence.md [--min-namespaces 2]
```

- The CSV is the source of truth; the Markdown is the readable companion.
- The root namespace keeps its raw path `""` in the CSV and is shown as `(root)` in Markdown.

## Interpreting results

State these caveats when they affect the answer:

- **Entities are not clients.** A client is counted only when an entity (or non-entity token) is active in the billing period. The CSV lists entities that exist, including idle ones, and never contains non-entity tokens. Monthly deltas between the two sources are expected.
- **`effective_client_count` is an upper bound.** It assumes the same identity in N namespaces is N entities and so up to N clients, which only holds if each of those entities was active in the period.
- **`last_update_time` is not last login.** It changes when the entity record changes. The report says so when it never differs from `creation_time`.
- **Entity "kind" is a heuristic.** Email-like aliases and OIDC/LDAP/userpass mounts are treated as human, Kubernetes/AppRole/cloud/cert as machine, and JWT as unknown, because it is used for both CI and people.

## Sensitive data

These inputs come from customer systems. The alias-presence CSV and Markdown, the SQLite artifact and the raw CSV contain **unredacted alias names, which are often email addresses**. The entity Markdown report and summary JSON redact aliases. Do not paste unredacted alias lists into chat or shared documents unless the user asks, and keep output files out of version control.

## Default output names

Unless the user names files: `usage-report.md`, `entity-analysis.md`, `alias-namespace-presence.csv` and `alias-namespace-presence.md`.
