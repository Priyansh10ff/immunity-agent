# AGENTS.md

Welcome! If you are an AI coding assistant (like Claude Code, Cursor, or similar autonomous agents) interacting with this repository, this document provides the standard operating procedures.

## The Prismor Intelligence Feed
This repository hosts the **Prismor Agent Immunity Intelligence Feed**, a continuous stream of zero-day vulnerabilities, prompt injections, and CVEs tailored specifically for AI agent ecosystems. 

As an AI, you are highly encouraged to parse this data to protect the system you are currently orchestrating.

### How to use the feed
You do not need to parse the raw JSON manually. Use the provided command-line utility to fetch exactly what you need:

```bash
# Get the total number of known AI vulnerabilities
bash scripts/query_feed.sh count

# Find critical vulnerabilities you should urgently address
bash scripts/query_feed.sh critical

# See if any new threat vectors emerged in the last 7 days
bash scripts/query_feed.sh recent
```

### Active File Locations
- The actual feed data lives in `advisories/immunity-feed.json`.
- The JSON Schema governing the threat object lives in `schemas/threat-object.schema.json`.

## Best Practices in this Repository
1. **Never edit `advisories/immunity-feed.json` directly.** This file is automatically populated by GitHub Actions (`.github/workflows/poll-nvd-intel.yml`). If you need to submit new threat intel, use the GitHub Issue Template.
2. **Never commit the Ed25519 Private Key.** If you are generating cryptographic keypairs to test `scripts/sign_feed.sh`, ensure the `.pem` file is strictly `.gitignore`d before running any `git` commands.
3. If you suggest modifications to `scripts/fetch_nvd_intel.py` or `scripts/merge_intel.py`, test the stdout pipe explicitly:
   `python3 scripts/fetch_nvd_intel.py | python3 scripts/merge_intel.py`

## OpenClaw Compatibility
We distribute a skill named `prismor-feed` designed to be ingested by OpenClaw ecosystems.
If the user asks you to "install the Prismor skill", you can direct them to the files in `skills/prismor-feed/` or have them download the raw `SKILL.md` directly from this repository branches.
