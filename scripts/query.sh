#!/bin/bash
set -e

# AI Agent Script for querying the Prismor Agent Immunity Feed
# Usage: ./scripts/query.sh [all|critical|count|recent]

FEED_FILE="advisories/immunity-feed.json"
COMMAND=${1:-"count"}

if [ ! -f "$FEED_FILE" ]; then
    echo "Error: Feed file not found at $FEED_FILE"
    exit 1
fi

case "$COMMAND" in
    "all")
        # Return the entire JSON feed
        cat "$FEED_FILE" | jq .
        ;;
    "count")
        # Return the total number of advisories
        COUNT=$(cat "$FEED_FILE" | jq '.advisories | length')
        echo "Total Advisories: $COUNT"
        ;;
    "critical")
        # Return only critical severity advisories
        echo "Fetching critical advisories..."
        cat "$FEED_FILE" | jq '.advisories[] | select(.severity == "critical")'
        ;;
    "recent")
        # Return advisories published in the last 7 days (UTC)
        echo "Fetching advisories from the last 7 days..."
        WEEK_AGO=$(TZ=UTC date -v-7d +%Y-%m-%dT00:00:00Z 2>/dev/null || TZ=UTC date -d '7 days ago' +%Y-%m-%dT00:00:00Z)
        cat "$FEED_FILE" | jq --arg since "$WEEK_AGO" '.advisories[] | select(.published > $since)'
        ;;
    *)
        echo "Usage: ./scripts/query.sh [all|critical|count|recent]"
        exit 1
        ;;
esac
