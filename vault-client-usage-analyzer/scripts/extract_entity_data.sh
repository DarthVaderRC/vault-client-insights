#!/usr/bin/env bash
#
# Export every Vault identity entity (root and all nested namespaces) to the CSV format
# expected by analyze_vault_entities.py and analyze_alias_namespace_presence.py.
#
# Prerequisites:
#   - vault CLI, authenticated (VAULT_ADDR + VAULT_TOKEN, or `vault login`)
#   - jq
#   - a token that can list sys/namespaces and read identity/entity/id/* in every namespace
#
# Usage: ./extract_entity_data.sh [output.csv]
#
# Multi-valued alias fields are joined with ";". Every field is CSV-quoted by jq, so
# metadata JSON and names containing commas or quotes are safe.

set -euo pipefail

OUTPUT="${1:-vault_entities.csv}"

for cmd in vault jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is required but not installed" >&2
        exit 1
    fi
done
if ! vault token lookup >/dev/null 2>&1; then
    echo "ERROR: unable to authenticate with Vault. Check VAULT_ADDR/VAULT_TOKEN or run 'vault login'" >&2
    exit 1
fi

# vault list exits non-zero when a path has no keys; treat that as an empty list.
vault_list() {
    local ns="$1" path="$2" out
    if [ -n "$ns" ]; then
        out=$(vault list -namespace="$ns" -format=json "$path" 2>/dev/null) || out='[]'
    else
        out=$(vault list -format=json "$path" 2>/dev/null) || out='[]'
    fi
    [ -n "$out" ] || out='[]'
    echo "$out" | jq -r '.[]'
}

# Depth-first walk of the namespace tree. Root is the empty string.
NAMESPACES=("")
walk_namespaces() {
    local parent="$1" child
    while IFS= read -r child; do
        [ -n "$child" ] || continue
        NAMESPACES+=("${parent}${child}")
        walk_namespaces "${parent}${child}"
    done < <(vault_list "$parent" sys/namespaces)
}
walk_namespaces ""
echo "Found ${#NAMESPACES[@]} namespaces (including root)" >&2

echo "entity_id,name,namespace_id,creation_time,last_update_time,alias_count,alias_id,alias_names,alias_mount_paths,alias_mount_types,disabled,metadata" > "$OUTPUT"

total=0
failed=0
for ns in "${NAMESPACES[@]}"; do
    echo "Processing namespace: ${ns:-(root)}" >&2
    ns_args=()
    [ -n "$ns" ] && ns_args=(-namespace="$ns")
    while IFS= read -r entity_id; do
        [ -n "$entity_id" ] || continue
        if ! entity_json=$(vault read ${ns_args[@]+"${ns_args[@]}"} -format=json "identity/entity/id/$entity_id" 2>/dev/null); then
            failed=$((failed + 1))
            continue
        fi
        echo "$entity_json" | jq -r '
            .data as $e
            | ($e.aliases // []) as $a
            | [
                $e.id, $e.name, $e.namespace_id, $e.creation_time, $e.last_update_time,
                ($a | length),
                ([$a[].id] | join(";")),
                ([$a[].name] | join(";")),
                ([$a[].mount_path] | join(";")),
                ([$a[].mount_type] | join(";")),
                ($e.disabled // false | tostring),
                ($e.metadata | tojson)
              ]
            | map(. // "" | tostring)
            | @csv' >> "$OUTPUT"
        total=$((total + 1))
    done < <(vault_list "$ns" identity/entity/id)
done

echo "Export complete: $OUTPUT ($total entities, $failed failed reads)" >&2
