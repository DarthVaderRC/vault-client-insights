#!/usr/bin/env python3
"""Generate a full alias+mount multi-namespace presence report for Vault entity exports."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


class CLIError(Exception):
    """Raised for user-facing CLI errors."""


REQUIRED_ENTITY_COLUMNS = {
    "entity_id",
    "namespace_id",
    "alias_count",
    "alias_names",
    "alias_mount_paths",
    "alias_mount_types",
}


def validate_input_file(path: Path, label: str) -> None:
    if not path.exists():
        raise CLIError(f"{label} not found: {path}")
    if not path.is_file():
        raise CLIError(f"{label} is not a file: {path}")


def prepare_output_path(path: Path, label: str) -> None:
    if path.exists() and path.is_dir():
        raise CLIError(f"Cannot write {label}: output path is a directory: {path}")

    parent = path.parent
    if parent.exists() and not parent.is_dir():
        raise CLIError(f"Cannot write {label}: parent path is not a directory: {parent}")

    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CLIError(f"Cannot create parent directory for {label} {path}: {exc}") from exc


def split_field(value: str | None) -> List[str]:
    if not value or value == "null":
        return []
    return value.split(";")


def is_masked_namespace(namespace_id: str, namespace_path: str) -> bool:
    namespace_id = (namespace_id or "").strip()
    namespace_path = (namespace_path or "").strip()
    if not namespace_id:
        return True
    if namespace_id == "root" and namespace_path == "":
        return False
    if not namespace_path:
        return True
    if namespace_id.startswith("ns-id-"):
        return True
    if "XXX" in namespace_path:
        return True
    return False


def load_namespace_map(usage_json_path: Path) -> Dict[str, str]:
    try:
        data = json.loads(usage_json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CLIError(
            f"Failed to parse JSON in {usage_json_path} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise CLIError(f"Failed to read usage JSON {usage_json_path}: {exc}") from exc
    namespace_map: Dict[str, str] = {"root": ""}

    def add_mapping(namespace: Dict[str, object]) -> None:
        namespace_id = str(namespace.get("namespace_id", "")).strip()
        namespace_path = str(namespace.get("namespace_path", "")).strip()
        if not is_masked_namespace(namespace_id, namespace_path):
            namespace_map.setdefault(namespace_id, namespace_path)

    by_namespace = data.get("data", {}).get("by_namespace", [])
    for namespace in by_namespace:
        add_mapping(namespace)

    months = data.get("data", {}).get("months", [])
    for month in months:
        for namespace in month.get("namespaces", []):
            add_mapping(namespace)

        for namespace in month.get("new_clients", {}).get("namespaces", []):
            add_mapping(namespace)

    return namespace_map


def iter_alias_rows(entity_csv_path: Path) -> Iterable[Dict[str, str]]:
    try:
        with entity_csv_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise CLIError(f"Entity CSV is empty or missing a header row: {entity_csv_path}")

            missing_columns = sorted(REQUIRED_ENTITY_COLUMNS - set(reader.fieldnames))
            if missing_columns:
                raise CLIError(
                    f"Entity CSV is missing required columns: {', '.join(missing_columns)}"
                )

            for row_number, raw in enumerate(reader, start=2):
                try:
                    alias_names = split_field(raw.get("alias_names"))
                    alias_mount_paths = split_field(raw.get("alias_mount_paths"))
                    alias_mount_types = split_field(raw.get("alias_mount_types"))
                    alias_count = int(raw.get("alias_count") or 0)
                    alias_len = max(alias_count, len(alias_names), len(alias_mount_paths), len(alias_mount_types))

                    for idx in range(alias_len):
                        alias_name = alias_names[idx].strip() if idx < len(alias_names) else ""
                        mount_path = alias_mount_paths[idx].strip() if idx < len(alias_mount_paths) else ""
                        mount_type = alias_mount_types[idx].strip() if idx < len(alias_mount_types) else ""
                        if not alias_name or not mount_path:
                            continue
                        yield {
                            "entity_id": raw["entity_id"],
                            "namespace_id": raw["namespace_id"].strip(),
                            "alias_name": alias_name,
                            "alias_mount_path": mount_path,
                            "alias_mount_type": mount_type,
                        }
                except ValueError as exc:
                    raise CLIError(f"Failed to parse entity CSV row {row_number}: {exc}") from exc
    except csv.Error as exc:
        raise CLIError(f"Failed to parse entity CSV {entity_csv_path}: {exc}") from exc
    except OSError as exc:
        raise CLIError(f"Failed to read entity CSV {entity_csv_path}: {exc}") from exc


def group_alias_presence(entity_csv_path: Path, namespace_map: Dict[str, str], min_namespaces: int) -> List[Dict[str, object]]:
    grouped: Dict[Tuple[str, str], Dict[str, object]] = {}

    for row in iter_alias_rows(entity_csv_path):
        alias_name = row["alias_name"]
        mount_path = row["alias_mount_path"]
        key = (alias_name.casefold(), mount_path.lower())

        if key not in grouped:
            grouped[key] = {
                "alias_name": alias_name,
                "alias_mount_path": mount_path,
                "alias_mount_types": set(),
                "namespace_ids": set(),
                "entity_ids": set(),
            }

        entry = grouped[key]
        entry["alias_mount_types"].add(row["alias_mount_type"])
        entry["namespace_ids"].add(row["namespace_id"])
        entry["entity_ids"].add(row["entity_id"])

    rows: List[Dict[str, object]] = []
    for entry in grouped.values():
        namespace_ids = sorted(entry["namespace_ids"], key=str.casefold)
        if len(namespace_ids) < min_namespaces:
            continue

        namespace_pairs = []
        namespace_paths = []
        unmapped_namespace_ids = []
        for namespace_id in namespace_ids:
            if namespace_id in namespace_map:
                namespace_path = namespace_map[namespace_id]
                namespace_paths.append(namespace_path)
                namespace_pairs.append(f"{namespace_id}:{namespace_path or '(root)'}")
            else:
                unmapped_namespace_ids.append(namespace_id)
                namespace_paths.append(f"[unmapped:{namespace_id}]")
                namespace_pairs.append(f"{namespace_id}:[unmapped]")

        rows.append(
            {
                "alias_name": entry["alias_name"],
                "alias_mount_path": entry["alias_mount_path"],
                "alias_mount_type": ";".join(sorted(t for t in entry["alias_mount_types"] if t)),
                "distinct_namespace_count": len(namespace_ids),
                "effective_client_count": len(namespace_ids),
                "entity_row_count": len(entry["entity_ids"]),
                "namespace_ids": ";".join(namespace_ids),
                "namespace_paths": ";".join(namespace_paths),
                "namespace_pairs": ";".join(namespace_pairs),
                "unmapped_namespace_ids": ";".join(unmapped_namespace_ids),
            }
        )

    rows.sort(
        key=lambda item: (
            -int(item["distinct_namespace_count"]),
            str(item["alias_name"]).casefold(),
            str(item["alias_mount_path"]).casefold(),
        )
    )
    return rows


def write_csv(rows: List[Dict[str, object]], output_path: Path) -> None:
    prepare_output_path(output_path, "CSV output")
    fieldnames = [
        "alias_name",
        "alias_mount_path",
        "alias_mount_type",
        "distinct_namespace_count",
        "effective_client_count",
        "entity_row_count",
        "namespace_ids",
        "namespace_paths",
        "namespace_pairs",
        "unmapped_namespace_ids",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def md_escape(value: str) -> str:
    return value.replace("|", "\\|")


def render_markdown(
    rows: List[Dict[str, object]],
    namespace_map: Dict[str, str],
    csv_path: Path,
    usage_json_path: Path,
    min_namespaces: int = 2,
) -> str:
    total_effective_clients = sum(int(row["effective_client_count"]) for row in rows)
    total_entity_rows = sum(int(row["entity_row_count"]) for row in rows)
    unmapped_ids = sorted(
        {
            namespace_id
            for row in rows
            for namespace_id in str(row["unmapped_namespace_ids"]).split(";")
            if namespace_id
        },
        key=str.casefold,
    )

    lines: List[str] = []
    lines.append("# Alias Namespace Presence")
    lines.append("")
    lines.append(f"**Entity source:** `{csv_path.name}`  ")
    lines.append(f"**Namespace mapping source:** `{usage_json_path.name}`")
    lines.append("")
    lines.append(f"This report lists every `alias_name + alias_mount_path` combination that appears in at least {min_namespaces} namespaces.")
    lines.append("")
    lines.append(
        "Assumption: entities are namespace-scoped, so the same person or workload signing in to a mount in N namespaces "
        "becomes N entities and can be counted as up to N clients. `effective_client_count` therefore equals "
        "`distinct_namespace_count` and is an upper bound."
    )
    lines.append("")
    lines.append(
        "Caveat: this is an inventory of entities that exist, not of activity. An entity only counts as a client in a "
        "billing period if it authenticated during that period, so compare with the counters activity data before "
        "quoting license impact."
    )
    lines.append("")
    lines.append("This report contains unredacted alias names (often email addresses). Handle it as personal data.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Multi-namespace alias+mount groups: **{len(rows):,}**")
    lines.append(f"- Total effective client count across those groups: **{total_effective_clients:,}**")
    lines.append(f"- Total entity rows represented by those groups: **{total_entity_rows:,}**")
    lines.append(f"- Namespace mappings resolved from JSON: **{len(namespace_map):,}**")
    lines.append(f"- Unmapped namespace IDs still present in results: **{len(unmapped_ids):,}**")
    if unmapped_ids:
        lines.append("")
        lines.append("Unmapped namespace IDs:")
        lines.append("")
        for namespace_id in unmapped_ids:
            lines.append(f"- `{namespace_id}`")
    lines.append("")
    lines.append("## Full List")
    lines.append("")
    lines.append("| Alias name | Mount path | Mount type | Distinct namespaces | Effective clients | Entity rows | Namespaces |")
    lines.append("|------------|------------|------------|--------------------:|------------------:|------------:|------------|")
    for row in rows:
        namespaces = "<br>".join(
            md_escape(item)
            for item in str(row["namespace_pairs"]).split(";")
            if item
        )
        lines.append(
            "| {alias} | `{mount_path}` | `{mount_type}` | {namespace_count} | {client_count} | {entity_rows} | {namespaces} |".format(
                alias=md_escape(str(row["alias_name"])),
                mount_path=md_escape(str(row["alias_mount_path"])),
                mount_type=md_escape(str(row["alias_mount_type"] or "-")),
                namespace_count=row["distinct_namespace_count"],
                client_count=row["effective_client_count"],
                entity_rows=row["entity_row_count"],
                namespaces=namespaces,
            )
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a full alias+mount multi-namespace presence listing.")
    parser.add_argument("entity_csv", type=Path, help="Path to the Vault entity CSV export")
    parser.add_argument("usage_json", type=Path, help="Path to the Vault usage JSON containing namespace mappings")
    parser.add_argument("--csv-out", type=Path, required=True, help="Path to write the CSV output")
    parser.add_argument("--md-out", type=Path, required=True, help="Path to write the Markdown output")
    parser.add_argument("--min-namespaces", type=int, default=2, help="Minimum distinct namespaces required to include a row")
    args = parser.parse_args()
    if args.min_namespaces < 1:
        parser.error("--min-namespaces must be >= 1")
    return args


def main() -> int:
    args = parse_args()

    try:
        validate_input_file(args.entity_csv, "Entity CSV")
        validate_input_file(args.usage_json, "Usage JSON")
        prepare_output_path(args.csv_out, "CSV output")
        prepare_output_path(args.md_out, "Markdown output")

        namespace_map = load_namespace_map(args.usage_json)
        rows = group_alias_presence(args.entity_csv, namespace_map, args.min_namespaces)
        write_csv(rows, args.csv_out)
        args.md_out.write_text(render_markdown(rows, namespace_map, args.entity_csv, args.usage_json, args.min_namespaces), encoding="utf-8")
        print(f"CSV output written to: {args.csv_out}", file=sys.stderr)
        print(f"Markdown output written to: {args.md_out}", file=sys.stderr)
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: failed to write output: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
