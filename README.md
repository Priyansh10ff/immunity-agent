# Prismor

![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-5865F2?logo=discord&logoColor=white)](https://discord.gg/8rBwhz6T)

**Security for AI coding agents.** A signed threat feed, agent-native security skills, and a local runtime monitor — in one package.

## Quick Start (30 seconds)

### Option A: One-liner setup

```bash
git clone https://github.com/PrismorSec/prismor.git ~/.prismor
bash ~/.prismor/scripts/init.sh .
```

This clones Prismor, detects your IDE (Claude Code, Cursor, or Windsurf), creates a `CLAUDE.md` with security skill references, and installs Warden runtime hooks. Done.

### Option B: Manual setup

```bash
git clone https://github.com/PrismorSec/prismor.git ~/.prismor
```

Then tell your agent:

```
Read ~/.prismor/skills/security.md and follow its instructions.
```

Or add this to your project's `CLAUDE.md`:

```markdown
## Security (Prismor)

At the start of every session, read `~/.prismor/skills/security.md` and follow its instructions.
```

### Option C: Runtime protection with Warden

```bash
cd your-project
python3 ~/.prismor/warden/cli.py install-hooks --agent claude --workspace . --mode observe
```

Replace `claude` with `cursor` or `windsurf` or `all`. Use `--mode enforce` to block dangerous actions.

## What You Get

### 1. Signed Threat Feed

A daily-updated, Ed25519-signed advisory feed covering AI-specific vulnerabilities.

```bash
bash ~/.prismor/scripts/query.sh count     # 217 advisories
bash ~/.prismor/scripts/query.sh critical  # critical-severity only
bash ~/.prismor/scripts/verify_feed.sh     # verify signature
```

**Coverage:** LangChain, LlamaIndex, OpenAI, Anthropic, CrewAI, AutoGPT, prompt injection patterns, jailbreaks, unsafe tool execution, and more.

**Feed types:** `unsafe_tool_execution` (33%), `prompt_injection` (29%), `data_exfiltration` (15%), `model_denial_of_service` (7%), `policy_bypass` (4%).

### 2. Security Skills

Agent-native security instructions your AI agent can follow at build time.

| Skill | What It Covers |
|-------|---------------|
| [Behavioral Security](skills/behavioral-security/SKILL.md) | Command deny-lists, secret protection, anti-prompt-injection, HITL gates |
| [Code Security](skills/code-security/SKILL.md) | OWASP Top 10 with 22 rule files across Python, JS, Java, Go, Ruby, C# |
| [LLM Security](skills/llm-security/SKILL.md) | OWASP Top 10 for LLMs 2025 (prompt injection, excessive agency, data poisoning...) |
| [Feed Integration](skills/prismor-feed/SKILL.md) | How to fetch, parse, and act on the live threat feed |
| [Static Analysis](skills/static-analysis/SKILL.md) | Pattern-based scanning, custom rule authoring, SARIF output |

Every rule file includes **vulnerable code** and **secure code** side by side, in real frameworks (Flask, Express, Spring, etc.), not pseudocode.

### 3. Warden Runtime Monitor

A local-first runtime monitor that hooks into your IDE to detect and block dangerous agent behavior.

```bash
# Analyze a session export
python3 warden/cli.py analyze --input session.jsonl

# Install hooks for all supported agents
python3 warden/cli.py install-hooks --agent all --workspace . --mode enforce

# View stored sessions
python3 warden/cli.py sessions --workspace .
```

**What Warden catches:**

| Category | Severity | Examples |
|----------|----------|---------|
| Destructive commands | CRITICAL | `rm -rf /`, `mkfs`, `dd if=...of=/dev/` |
| Secret exfiltration | CRITICAL | `cat .env \| curl ...` |
| Prompt injection | HIGH | "ignore all instructions", "reveal system prompt" |
| Remote execution | HIGH | `curl \| bash`, `wget \| sh` |
| Sensitive file access | HIGH | `.ssh/id_rsa`, `.aws/credentials`, `.env` |
| Risky file writes | MEDIUM-HIGH | Dockerfile, CI workflows, package manifests |
| Suspicious network | HIGH | webhook.site, ngrok, pastebin, Discord webhooks |

**Supported agents:** Claude Code, Cursor, Windsurf. Two modes: `observe` (log only) and `enforce` (block + log).

## Integration Templates

For projects that don't use the `init.sh` script, we provide copy-paste templates:

- [`templates/CLAUDE.md.template`](templates/CLAUDE.md.template) — add Prismor to any Claude Code project
- [`templates/.cursorrules.template`](templates/.cursorrules.template) — add Prismor to any Cursor project

## Repository Layout

```
prismor/
├── advisories/     Signed AI-security threat feed
├── keys/           Public key for feed signature verification
├── pipeline/       NVD fetch, merge, sign automation (GitHub Actions)
├── scripts/        init.sh, query.sh, verify_feed.sh, upgrade_feed.py
├── skills/         Agent-readable security skills (5 skill sets, 32+ rule files)
├── templates/      Integration templates for CLAUDE.md, .cursorrules
└── warden/         Local session-security runtime (hooks, policies, SQLite storage)
```

## How The Feed Pipeline Works

```
NVD API → fetch_nvd_intel.py → merge_intel.py → sign_feed.sh → immunity-feed.json
```

Runs daily via GitHub Actions. Queries 8 AI-ecosystem keywords against NVD, maps CWEs to AI threat types, extracts meaningful titles and actionable remediation, validates against JSON schema, and signs with Ed25519.

## Verify Feed Integrity

```bash
bash scripts/verify_feed.sh
```

The public key is at [`keys/public.pub`](keys/public.pub). The signature is a detached Ed25519 signature, base64-encoded.

## Credits

The code security and LLM security rules are adapted from the [Semgrep Skills repository](https://github.com/semgrep/skills) (Apache-2.0). We also acknowledge the [OWASP Foundation](https://owasp.org/) for the Top 10 and LLM Top 10 projects.

## Community

- [Discord](https://discord.gg/8rBwhz6T) — share findings, discuss agent security
- [Prismor.dev](https://prismor.dev) — full platform with cloud scanning, SBOM, AI-powered fixes
- Found a threat? Open an issue using the **Threat Intelligence** template.
