#!/usr/bin/env python3
"""Retroactively upgrade existing feed advisories with better titles, types, actions, and deduplicated references."""

import json
import os
import sys
from datetime import datetime, timezone

# Add parent dir to path so we can import the pipeline module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.fetch_nvd_intel import (
    TYPE_ACTION_MAP,
    extract_title,
    map_cwe_to_type,
)

FEED_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "advisories", "immunity-feed.json")


def upgrade_advisory(adv):
    """Upgrade a single advisory with better title, type, action, and deduplicated references."""
    description = adv.get("description", "")
    old_type = adv.get("type", "unknown")

    # Re-classify unknown types using description-based fallback
    if old_type == "unknown":
        new_type = map_cwe_to_type([], description=description)
    else:
        new_type = old_type

    # Upgrade generic titles
    old_title = adv.get("title", "")
    if old_title.startswith("NVD Entry for "):
        new_title = extract_title(adv["id"], description)
    else:
        new_title = old_title

    # Upgrade generic actions
    old_action = adv.get("action", "")
    if old_action == "Investigate and update affected component.":
        new_action = TYPE_ACTION_MAP.get(new_type, TYPE_ACTION_MAP["unknown"])
    else:
        new_action = old_action

    # Deduplicate references
    old_refs = adv.get("references", [])
    new_refs = list(dict.fromkeys(old_refs))

    adv["type"] = new_type
    adv["title"] = new_title
    adv["action"] = new_action
    adv["references"] = new_refs
    return adv


def main():
    with open(FEED_PATH, "r") as f:
        feed = json.load(f)

    advisories = feed.get("advisories", [])
    total = len(advisories)

    stats = {"type_upgraded": 0, "title_upgraded": 0, "refs_deduped": 0}

    for adv in advisories:
        old_type = adv["type"]
        old_title = adv["title"]
        old_ref_count = len(adv.get("references", []))

        upgrade_advisory(adv)

        if adv["type"] != old_type:
            stats["type_upgraded"] += 1
        if adv["title"] != old_title:
            stats["title_upgraded"] += 1
        if len(adv.get("references", [])) < old_ref_count:
            stats["refs_deduped"] += 1

    feed["updated"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    with open(FEED_PATH, "w") as f:
        json.dump(feed, f, indent=2)

    # Report
    unknown_remaining = sum(1 for a in advisories if a["type"] == "unknown")
    print(f"Feed upgraded: {total} advisories", file=sys.stderr)
    print(f"  Types reclassified:    {stats['type_upgraded']}", file=sys.stderr)
    print(f"  Titles improved:       {stats['title_upgraded']}", file=sys.stderr)
    print(f"  References deduped:    {stats['refs_deduped']}", file=sys.stderr)
    print(f"  Still unknown type:    {unknown_remaining}/{total} ({100*unknown_remaining/total:.1f}%)", file=sys.stderr)

    # Show type distribution
    from collections import Counter
    type_counts = Counter(a["type"] for a in advisories)
    print(f"\nType distribution:", file=sys.stderr)
    for t, c in type_counts.most_common():
        print(f"  {t}: {c}", file=sys.stderr)


if __name__ == "__main__":
    main()
