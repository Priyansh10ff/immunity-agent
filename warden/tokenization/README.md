# Warden Tokenize

**Prevention layer for secrets in AI coding agents.** Keeps real secret values out of the model's context, the on-disk JSONL transcript, and the upstream LLM API — while still letting the agent use those secrets to execute local tool calls.

Complements `warden sweep` (post-hoc disk-residue cleanup) by stopping leaks at the tool boundary in real time.

---

## How it works

You enroll a real secret once under a human-readable placeholder:

```bash
warden tokenize add stripe_key    # value read from stdin, never argv
```

From that point on, the model refers to the secret as `@@SECRET:stripe_key@@`. When the agent emits a tool call containing that placeholder, Warden's `PreToolUse` hook:

1. Substitutes the placeholder with the real value in the command that is actually executed locally.
2. Wraps the command so its captured stdout/stderr passes through a `sed` filter that scrubs the real value *back* to the placeholder before Claude Code records it.

Result: the real secret is resident only inside the hook process and the local subprocess. The model, the JSONL transcript (`~/.claude/projects/<cwd>/*.jsonl`), and every upstream API request see only the placeholder.

```
            ┌──────────────────────────────── real value never here ──┐
            │                                                          │
User ──► Claude API ──► tool_use("@@SECRET:stripe_key@@")               │
                             │                                          │
                             ▼                                          │
                    PreToolUse hook                                     │
                    detokenize + wrap                                   │
                             │                                          │
                             ▼                                          │
                 bash -c "( real cmd ) 2>&1 | sed s|REAL|@@...|g"       │
                             │                                          │
                             ▼                                          │
                  captured stdout (scrubbed) ──► tool_result ◄──────────┘
```

---

## Install

From inside a project:

```bash
warden tokenize install
```

This merges four hook entries into `.claude/settings.json` (preserving any Warden runtime-monitor hooks already there):

| Event | Matcher | Script | Purpose |
|---|---|---|---|
| `PreToolUse` | `Bash` | `detokenize.sh` | Substitute placeholders, wrap with `sed` |
| `PostToolUse` | `mcp__.*` | `retokenize-mcp.sh` | Scrub real values from MCP responses |
| `UserPromptSubmit` | — | `userprompt-guard.sh` | Soft-block + auto-tokenize pasted secrets |
| `Stop` (opt) | — | `sweep-on-stop.sh` | Dry-run sweep for residue (off by default) |

Flags:

```bash
warden tokenize install --scope user           # install globally in ~/.claude
warden tokenize install --no-userprompt-guard  # skip the paste-detection hook
warden tokenize install --sweep-on-stop        # add the Stop-hook sweep
```

Uninstall leaves unrelated Claude Code settings untouched:

```bash
warden tokenize uninstall
```

---

## Managing secrets

```bash
# Register — value is read from stdin (or hidden prompt if interactive)
warden tokenize add stripe_key          # prompts you to paste the value
printf '%s' "$(cat ~/.keys/stripe)" | warden tokenize add stripe_key
warden tokenize add aws_prod --from-file ~/.keys/aws

# List registered placeholder names — NEVER shows values
warden tokenize list

# Delete a registered secret (any tool call still referencing it will fail closed)
warden tokenize remove stripe_key

# Show install state
warden tokenize status
```

Secrets live under `$PRISMOR_HOME/secrets/` (default `~/.prismor/secrets/`) with the directory at `0700` and each file at `0600`. The directory should be **excluded from backups and sync** (Time Machine, iCloud, Dropbox). Override the location with `PRISMOR_SECRETS_DIR`.

---

## The user-prompt boundary

`UserPromptSubmit` hooks cannot *rewrite* a prompt in Claude Code — they can only block or add context. When you paste a prompt containing a recognizable secret (Stripe key, GitHub PAT, AWS access key, Slack token, GitLab PAT, JWT, …), the `userprompt-guard.sh` hook:

1. Detects the secret via conservative, known-prefix regex.
2. Auto-registers it under a deterministic hashed name (`auto_<8-hex>`) in `$PRISMOR_SECRETS_DIR`.
3. Blocks the submission with a message that shows the **sanitized** prompt, ready for you to copy and resubmit.

The UX cost is one re-paste per leaked prompt. The original prompt was *not* transmitted to the upstream API.

**Bypass:** prefix any prompt with `!!allow ` to skip detection for a single message (useful when you are deliberately discussing a secret format in prose).

---

## What this does *not* protect

Enumerated honestly so you know what to layer on top:

1. **Hand-typed secrets shorter than ~16 chars.** No prefix, too short for entropy heuristics, indistinguishable from benign text.
2. **Secrets generated mid-turn** (`openssl rand`, `aws iam create-access-key`, `ssh-keygen`). The sed-wrap scrubber only knows about values already in `$PRISMOR_SECRETS_DIR`; a freshly minted value flows through unscrubbed.
3. **The secrets directory itself**, if committed, synced, or backed up without exclusion. Treat it as a single point of failure.
4. **Built-in `Read` of secret-bearing files.** `PostToolUse` can only rewrite MCP tool output, not built-in Read. Add a `permissions.deny` rule under `Read(./secrets/**)` in your Claude settings to close this gap, and route secret access through the placeholder syntax instead.
5. **Assistant-side narration.** If the model already saw a real value (through paste, Read, or a command that bypassed the wrapper), it can echo the value in prose. Hooks cannot filter assistant text. Use `/clear` immediately after any suspected leak.

For residue that slips through despite all of the above, run:

```bash
warden sweep            # dry-run scan
warden sweep --redact   # scan + encrypted-vault redact
```

---

## Layering with Warden runtime monitor

Tokenize and Warden's runtime monitor coexist on the same `.claude/settings.json`. Install order does not matter; each feature merges its own matcher blocks and uninstall strips only its own entries. Recommended combination:

```bash
warden install-hooks --agent claude --mode enforce   # policy enforcement
warden tokenize install                              # secret prevention
```

Then on a cadence (or via the opt-in `--sweep-on-stop` flag above):

```bash
warden sweep --redact
```

---

## Files shipped in this module

```
warden/tokenization/
├── __init__.py             # public API re-exports
├── installer.py            # install/uninstall settings.json merger
├── secrets_store.py        # add/list/remove operations on $PRISMOR_SECRETS_DIR
├── hooks/
│   ├── detokenize.sh       # PreToolUse:Bash
│   ├── retokenize-mcp.sh   # PostToolUse:mcp__.*
│   ├── userprompt-guard.sh # UserPromptSubmit soft-block
│   └── sweep-on-stop.sh    # Stop (opt-in)
└── README.md               # this file
```

Hook scripts are pure bash and depend only on `jq`. No Python startup cost on the hot path.
