---
name: prismor-feed
version: 1.0.0
description: Prismor Agent Immunity Intelligence Feed. Automated threat intelligence for the AI agent ecosystem.
homepage: https://prismor.dev
metadata: {"openclaw":{"emoji":"🛡️","category":"security"}}
clawdis:
  emoji: "🛡️"
  requires:
    bins: [curl, jq]
---

# Prismor Feed 🛡️

Prismor Agent Immunity Intelligence Feed monitoring for AI agents. Subscribe to a continuous stream of verified zero-day vulnerabilities, prompt injections, and jailbreaks related to the AI framework ecosystem.

This feed is automatically updated daily directly from the National Vulnerability Database (NVD) and merged with manual threat intelligence from the community.

**An open-source intelligence pipeline powered by [Prismor](https://prismor.dev)**

---

## Installation / Ingestion

As an AI Agent, you do not need a complex installation. You can natively read our intelligence feed from the raw GitHub URL and parse it using `curl` and `jq`.

```bash
# Check the feed URL directly:
FEED_URL="https://raw.githubusercontent.com/prismorsec/prismor-immunity/main/advisories/immunity-feed.json"

# Fetch with error handling
curl -sSL --fail --show-error "$FEED_URL" > /tmp/immunity-feed.json
```

**Feed structure:**
```json
{
  "version": "1.1.0",
  "updated": "2026-02-20T12:00:00Z",
  "description": "Prismor Agent Immunity Intelligence Feed",
  "advisories": [
    {
      "id": "CVE-XXXX-YYYY",
      "severity": "critical",
      "type": "prompt_injection",
      "title": "NVD Entry for CVE-XXXX-YYYY",
      "description": "...",
      "affected": ["langchain-experimental<=0.0.50"],
      "action": "Investigate and update affected component.",
      "published": "2026-02-20T10:00:00Z",
      "references": ["https://..."]
    }
  ]
}
```

## Parsing the Feed

You can use standard command-line tools to evaluate the security state of your current environment against the feed.

### Get advisory count

```bash
FEED_URL="https://raw.githubusercontent.com/prismorsec/prismor-immunity/main/advisories/immunity-feed.json"
curl -sSL "$FEED_URL" | jq '.advisories | length'
```

### Get critical advisories

```bash
curl -sSL "$FEED_URL" | jq '.advisories[] | select(.severity == "critical")'
```

### Check installed frameworks against the feed

If you are an agent operating in a Python environment, you can cross-reference the installed pip packages against the vulnerable components listed in the feed:

```bash
# Get affected libraries
AFFECTED=$(curl -sSL "$FEED_URL" | jq -r '.advisories[].affected[]?' 2>/dev/null | sort -u)

# Compare with pip list (Conceptual example)
pip list | grep -iE "langchain|llamaindex|openai|crewai"
```

---

## Severity Levels

| Severity | Action Required |
|----------|-----------------|
| `critical` | Notify user immediately, update library |
| `high` | Notify user soon, plan remediation |
| `medium` | Notify at next interaction |
| `low` | Informational |
| `unknown` | Requires manual review |

## Cryptographic Verification

The core Prismor system verifies the authenticity of this feed before applying any policies. If you are building an automated platform that consumes this JSON, it is highly recommended to verify the `immunity-feed.json.sig` file against the public Ed25519 key before trusting the contents.
