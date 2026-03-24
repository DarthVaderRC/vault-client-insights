#!/bin/bash

# Vault Entity Extractor (JWT/OIDC Only)
# Extracts entities with jwt or oidc auth aliases and their metadata, one row per alias.
#
# NOTE: this is an ad hoc helper for JWT/OIDC investigations. Its CSV schema is NOT the one
# the vault-client-usage-analyzer scripts read; use
# vault-client-usage-analyzer/scripts/extract_entity_data.sh for that. It also only reads
# a single namespace (VAULT_NAMESPACE, or root).
#
# Prerequisites:
#   - VAULT_ADDR environment variable set
#   - VAULT_TOKEN environment variable set (or logged in via vault login)
#   - jq installed for JSON parsing
#
# Usage: ./extract_vault_entities.sh [output_file.csv]

set -e

# Configuration
OUTPUT_FILE="${1:-vault_jwt_oidc_entities_$(date +%Y%m%d_%H%M%S).csv}"
NAMESPACE="${VAULT_NAMESPACE:-}"  # Optional namespace

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
check_prerequisites() {
    if [ -z "$VAULT_ADDR" ]; then
        echo -e "${RED}ERROR: VAULT_ADDR environment variable is not set${NC}"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: jq is required but not installed${NC}"
        exit 1
    fi

    if ! command -v vault &> /dev/null; then
        echo -e "${RED}ERROR: vault CLI is required but not installed${NC}"
        exit 1
    fi

    # Test vault connectivity
    if ! vault token lookup &> /dev/null; then
        echo -e "${RED}ERROR: Unable to authenticate with Vault. Check VAULT_TOKEN or run 'vault login'${NC}"
        exit 1
    fi

    echo -e "${GREEN}Prerequisites check passed${NC}"
    echo "Vault Address: $VAULT_ADDR"
    [ -n "$NAMESPACE" ] && echo "Namespace: $NAMESPACE"
}

# List all entity IDs
list_entity_ids() {
    echo -e "${YELLOW}Fetching entity IDs...${NC}"
    
    local ns_header=""
    [ -n "$NAMESPACE" ] && ns_header="-namespace=$NAMESPACE"
    
    # Use vault CLI to list entities
    local result
    result=$(vault list -format=json $ns_header identity/entity/id 2>/dev/null || echo '[]')
    
    echo "$result" | jq -r '.[]' 2>/dev/null || echo ""
}

# Read entity details by ID
read_entity() {
    local entity_id="$1"
    local ns_header=""
    [ -n "$NAMESPACE" ] && ns_header="-namespace=$NAMESPACE"
    
    vault read -format=json $ns_header "identity/entity/id/$entity_id" 2>/dev/null
}

# Check if entity has jwt or oidc aliases
has_jwt_oidc_alias() {
    local json_data="$1"
    
    # Returns "true" if any alias has mount_type jwt or oidc
    echo "$json_data" | jq -r '
        .data.aliases // [] | 
        map(select(.mount_type == "jwt" or .mount_type == "oidc")) | 
        length > 0
    '
}

# Extract entity data for CSV - one row per jwt/oidc alias
extract_entity_fields() {
    local json_data="$1"
    
    # Extract fields using jq - produces one CSV row per jwt/oidc alias
    echo "$json_data" | jq -r '
        .data as $entity |
        ($entity.aliases // []) | 
        map(select(.mount_type == "jwt" or .mount_type == "oidc")) |
        .[] |
        [
            $entity.id // "",
            $entity.name // "",
            $entity.namespace_id // "",
            $entity.creation_time // "",
            $entity.last_update_time // "",
            .id // "",
            .name // "",
            .mount_type // "",
            .mount_path // "",
            .mount_accessor // "",
            .creation_time // "",
            .last_update_time // "",
            (.metadata.role // ""),
            ((.metadata // {}) | to_entries | map("\(.key)=\(.value)") | join(";")),
            (($entity.policies // []) | join(";")),
            (($entity.group_ids // []) | join(";")),
            $entity.disabled // false
        ] | @csv
    '
}

# Main execution
main() {
    echo "========================================"
    echo "Vault Entity Extractor (JWT/OIDC Only)"
    echo "========================================"
    echo ""
    
    check_prerequisites
    echo ""
    
    # Get all entity IDs
    local entity_ids
    entity_ids=$(list_entity_ids)
    
    if [ -z "$entity_ids" ]; then
        echo -e "${YELLOW}No entities found${NC}"
        exit 0
    fi
    
    local total_entities
    total_entities=$(echo "$entity_ids" | wc -l | tr -d ' ')
    echo -e "${GREEN}Found $total_entities total entities${NC}"
    echo -e "${BLUE}Filtering for jwt/oidc mount types...${NC}"
    echo ""
    
    # Create CSV header
    echo "entity_id,entity_name,namespace_id,entity_creation_time,entity_last_update_time,alias_id,alias_name,mount_type,mount_path,mount_accessor,alias_creation_time,alias_last_update_time,role,alias_metadata,policies,group_ids,disabled" > "$OUTPUT_FILE"
    
    # Process each entity
    local count=0
    local matched=0
    local failed=0
    local alias_count=0
    
    echo -e "${YELLOW}Processing entities...${NC}"
    
    while IFS= read -r entity_id; do
        [ -z "$entity_id" ] && continue
        
        count=$((count + 1))
        
        # Progress indicator
        if [ $((count % 50)) -eq 0 ] || [ "$count" -eq "$total_entities" ]; then
            echo -ne "\rProcessed $count / $total_entities entities (matched: $matched, aliases: $alias_count)"
        fi
        
        # Read entity details
        local entity_json
        entity_json=$(read_entity "$entity_id")
        
        if [ -z "$entity_json" ] || [ "$entity_json" == "null" ]; then
            failed=$((failed + 1))
            continue
        fi
        
        # Check if entity has jwt/oidc aliases
        local has_match
        has_match=$(has_jwt_oidc_alias "$entity_json")
        
        if [ "$has_match" != "true" ]; then
            continue
        fi
        
        matched=$((matched + 1))
        
        # Extract and append to CSV (may produce multiple rows for multiple aliases)
        local csv_rows
        csv_rows=$(extract_entity_fields "$entity_json")
        
        if [ -n "$csv_rows" ]; then
            echo "$csv_rows" >> "$OUTPUT_FILE"
            # Count aliases added
            local rows_added
            rows_added=$(echo "$csv_rows" | wc -l | tr -d ' ')
            alias_count=$((alias_count + rows_added))
        else
            failed=$((failed + 1))
        fi
        
    done <<< "$entity_ids"
    
    echo ""
    echo ""
    echo "========================================"
    echo -e "${GREEN}Export Complete${NC}"
    echo "========================================"
    echo "Total entities scanned:    $count"
    echo "Entities with jwt/oidc:    $matched"
    echo "Total alias records:       $alias_count"
    echo "Failed reads:              $failed"
    echo "Output file:               $OUTPUT_FILE"
    echo ""
    
    # Show sample of output
    if [ -f "$OUTPUT_FILE" ]; then
        local line_count
        line_count=$(wc -l < "$OUTPUT_FILE")
        echo "CSV contains $((line_count - 1)) alias records (plus header)"
        echo ""
        
        if [ "$line_count" -gt 1 ]; then
            echo "Sample output (first 5 rows):"
            echo "---"
            head -1 "$OUTPUT_FILE" | tr ',' '\n' | nl -ba
            echo "---"
            head -6 "$OUTPUT_FILE" | tail -5
        fi
    fi
}

# Run main function
main "$@"
