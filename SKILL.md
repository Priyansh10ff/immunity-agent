---
name: immunity-agent
description: Use when setting up or working with Prismor Warden runtime security — installs policy enforcement, secret prevention, and supply-chain blocking for AI coding agents.
---

# immunity-agent: Runtime Security for AI Coding Agents

## What It Does

Warden runs as a hook layer that monitors every tool call your coding agent makes. It enforces security policies before the agent executes an action, preventing:

- **Secret exfiltration** — blocks reads of `.env`, credential files, and raw secret values
- **Dangerous shell commands** — blocks `rm -rf`, sudoers edits, CI pipeline modifications
- **Supply-chain attacks** — scans npm/pip packages against a signed threat feed before install
- **Prompt injection** — intercepts user-prompt payloads and flags injected instructions

## Setup (run once per machine)

```bash
pip install immunity-agent
immunity setup          # interactive 5-step onboarding wizard
```

Pass `--non-interactive` for CI or scripted installs.

## Modes

| Mode | Behavior |
|---|---|
| `observe` (default) | Logs all tool calls and findings. Never blocks. Safe for onboarding and auditing. |
| `enforce` | Blocks dangerous actions in real time before the agent executes them. |

Switch modes at any time:

```bash
immunity install-hooks --agent all --mode enforce    # block dangerous actions
immunity install-hooks --agent all --mode observe    # log only
```

## Key Commands

```bash
immunity audit          # security audit of current session logs
warden logs           # tail live session log
immunity status         # show hook installation and mode status
immunity cloak add KEY  # register a secret for cloaking
```

## Secret Cloaking

Real secret values live under `~/.prismor/secrets/`. Reference them in tool calls as `@@SECRET:<name>@@` and the hook substitutes the real value at runtime without exposing it in context or transcripts.

```bash
immunity cloak add stripe_key    # prompts for the value, stores it encrypted
# then use @@SECRET:stripe_key@@ in commands — never the raw value
```

## Agent Behavior Rules

- If Warden blocks an action, investigate the reason — do **not** attempt to bypass the hook or pass `--no-verify`
- Reference secrets as `@@SECRET:<name>@@` rather than raw values in all tool calls
- Run `immunity audit` after completing multi-step tasks to verify no policy violations occurred
- If `immunity setup` has not been run, run it before proceeding with any agent task in the workspace
