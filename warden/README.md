# Prismor Warden

Prismor Warden is a local utility for securing AI coding-agent sessions.

It installs hooks into supported agents, captures security-relevant session events, evaluates those events with deterministic rules, stores the results in SQLite, and correlates them with the local Prismor advisory feed.

It is part of the main Prismor package, not a separate product. Use it when you want runtime visibility and enforcement on top of the Prismor feed and skills.

## What It Does

- blocks obviously dangerous pre-action behavior in enforce mode
- records prompts, tool calls, file access, shell commands, and network actions
- flags prompt injection, secret access, exfiltration, destructive commands, and risky writes
- stores sessions, events, and findings in a local SQLite database
- shows recent sessions and detailed session reports in the terminal
- attaches matching advisory types from `advisories/immunity-feed.json`

## Supported Agents

- Claude Code
- Cursor
- Windsurf

## How To Use It

From the repo root:

```bash
python3 warden/cli.py analyze --input warden/examples/sample-session.jsonl
python3 warden/cli.py ingest --input warden/examples/sample-session.jsonl
python3 warden/cli.py sessions --workspace "$(pwd)"
python3 warden/cli.py session --workspace "$(pwd)" --session-id <id>
python3 warden/cli.py install-hooks --agent all --workspace "$(pwd)" --mode enforce
```

### Typical flow

1. Analyze a session export:

```bash
python3 warden/cli.py analyze --input warden/examples/sample-session.jsonl
```

2. Store it locally:

```bash
python3 warden/cli.py ingest --input warden/examples/sample-session.jsonl --workspace "$(pwd)"
```

3. Review stored sessions:

```bash
python3 warden/cli.py sessions --workspace "$(pwd)"
python3 warden/cli.py session --workspace "$(pwd)" --session-id <id>
```

4. Turn on live runtime blocking for supported agents:

```bash
python3 warden/cli.py install-hooks --agent all --workspace "$(pwd)" --scope project --mode enforce
```

Project-level hook installation writes:

- `.claude/settings.json`
- `.cursor/hooks.json`
- `.windsurf/hooks.json`

Warden state is stored under:

- `.prismor-warden/warden.db`
- `.prismor-warden/sessions/*.jsonl`

## Security Model

The current policy engine focuses on:

- prompt-injection and system-prompt extraction attempts
- destructive shell commands
- remote fetch-and-execute patterns
- direct reads and writes involving sensitive paths
- likely secret exfiltration flows
- writes to CI, container, and dependency manifests

## What Should Be Added Next

Warden should be hardened further in a few specific ways:

- encrypted local storage for session logs and findings at rest
- redaction before persistence so secrets never land in SQLite in cleartext
- allowlists for outbound domains and tool names per workspace
- feed-signature verification before advisory correlation
- uninstall and status commands for hook lifecycle management
- stricter path scoping so user-level installs cannot silently monitor unrelated directories
- policy versioning and signed local policy bundles
- optional quarantine mode for risky sessions instead of only blocking a single action
