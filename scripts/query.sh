#!/bin/bash
set -e

# Query the Prismor Agent Immunity Feed
# Usage: ./scripts/query.sh <command> [args]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FEED_FILE="${SCRIPT_DIR}/../advisories/immunity-feed.json"
COMMAND=${1:-"help"}
ARG=${2:-""}

if [ ! -f "$FEED_FILE" ]; then
    echo "Error: Feed file not found at $FEED_FILE"
    exit 1
fi

case "$COMMAND" in
    "count")
        COUNT=$(jq '.advisories | length' "$FEED_FILE")
        UPDATED=$(jq -r '.updated' "$FEED_FILE")
        echo "Total advisories: $COUNT"
        echo "Last updated:     $UPDATED"
        ;;

    "stats")
        echo "=== Feed Statistics ==="
        jq -r '.updated as $u | "Last updated: \($u)\n" ,
            "Severity breakdown:",
            (.advisories | group_by(.severity) | map("  \(.[0].severity): \(length)") | .[] ),
            "",
            "Type breakdown:",
            (.advisories | group_by(.type) | sort_by(-length) | map("  \(.[0].type): \(length)") | .[] )
        ' "$FEED_FILE"
        ;;

    "critical"|"high"|"medium"|"low")
        jq --arg sev "$COMMAND" \
            '[.advisories[] | select(.severity == $sev)] | sort_by(.published) | reverse | .[] | {id, type, title}' \
            "$FEED_FILE"
        ;;

    "severity")
        if [ -z "$ARG" ]; then
            echo "Usage: query.sh severity <critical|high|medium|low>"
            exit 1
        fi
        jq --arg sev "$ARG" \
            '[.advisories[] | select(.severity == $sev)] | sort_by(.published) | reverse | .[] | {id, type, title}' \
            "$FEED_FILE"
        ;;

    "type")
        if [ -z "$ARG" ]; then
            echo "Available types:"
            jq -r '[.advisories[].type] | unique | .[]' "$FEED_FILE"
            echo ""
            echo "Usage: query.sh type <type_name>"
            exit 0
        fi
        jq --arg t "$ARG" \
            '[.advisories[] | select(.type == $t)] | sort_by(.published) | reverse | .[] | {id, severity, title}' \
            "$FEED_FILE"
        ;;

    "search")
        if [ -z "$ARG" ]; then
            echo "Usage: query.sh search <keyword>"
            exit 1
        fi
        jq --arg q "$ARG" \
            '[.advisories[] | select(
                (.title | ascii_downcase | contains($q | ascii_downcase)) or
                (.description | ascii_downcase | contains($q | ascii_downcase)) or
                (.id | ascii_downcase | contains($q | ascii_downcase))
            )] | sort_by(.published) | reverse | .[] | {id, severity, type, title}' \
            "$FEED_FILE"
        ;;

    "id")
        if [ -z "$ARG" ]; then
            echo "Usage: query.sh id <CVE-XXXX-YYYY>"
            exit 1
        fi
        jq --arg id "$ARG" '.advisories[] | select(.id == $id)' "$FEED_FILE"
        ;;

    "recent")
        DAYS="${ARG:-7}"
        echo "Advisories from the last $DAYS days:"
        SINCE=$(python3 -c "from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=$DAYS)).strftime('%Y-%m-%dT00:00:00'))" 2>/dev/null || \
               date -v-${DAYS}d -u +%Y-%m-%dT00:00:00 2>/dev/null || \
               date -d "$DAYS days ago" -u +%Y-%m-%dT00:00:00)
        jq --arg since "$SINCE" \
            '[.advisories[] | select(.published > $since)] | sort_by(.published) | reverse | .[] | {id, severity, type, title, published}' \
            "$FEED_FILE"
        ;;

    "all")
        jq '.' "$FEED_FILE"
        ;;

    "help"|"--help"|"-h"|*)
        cat <<'EOF'
Prismor Feed Query Tool

Usage: query.sh <command> [argument]

Commands:
  count                 Show total advisories and last update time
  stats                 Show severity and type breakdown
  critical              List critical-severity advisories
  high                  List high-severity advisories
  medium                List medium-severity advisories
  low                   List low-severity advisories
  severity <level>      Filter by severity (critical, high, medium, low)
  type [name]           Filter by threat type (or list available types)
  search <keyword>      Search titles, descriptions, and IDs
  id <CVE-XXXX-YYYY>    Show full details for a specific advisory
  recent [days]         Show advisories from the last N days (default: 7)
  all                   Dump the entire feed
  help                  Show this help message

Examples:
  query.sh stats
  query.sh search LangChain
  query.sh type prompt_injection
  query.sh id CVE-2023-29374
  query.sh recent 30
EOF
        ;;
esac
