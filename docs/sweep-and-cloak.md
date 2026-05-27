# Sweep and Cloak

Sweep and Cloak are complementary. Cloak prevents secrets from entering model context in the first place. Sweep cleans up anything that already leaked into AI tool caches.

<img width="1820" height="796" alt="image" src="https://github.com/user-attachments/assets/68137da9-5e7a-4228-b55a-ec50b5cabd51" />

## Sweep

Sweep scans the local config directories of Claude, Cursor, Windsurf, Codex, and others for secrets that have already leaked. It finds API keys, tokens, and credentials, then lets you redact or delete them. Redacted values are saved to an AES-256 encrypted vault so you can restore them if needed.

```bash
immunity sweep              # dry run, shows what's exposed
immunity sweep --redact     # redact in place, save to vault
immunity sweep --clean      # delete files containing secrets
immunity sweep --restore --all
```

## Cloak

Cloak works at the tool boundary. You register a real secret once under a placeholder (`@@SECRET:name@@`). A `PreToolUse` hook substitutes the real value only at execution time, then scrubs it back out of captured output before the model sees it. The value never appears in the conversation transcript or any upstream API request. Pasted secrets are intercepted automatically.

```bash
immunity cloak install                        # install hooks into .claude/settings.json
immunity cloak add stripe_key                 # register a secret (read from stdin)
immunity cloak add aws_prod --from-file ~/.keys/aws
immunity cloak list                           # show registered placeholder names
immunity cloak status
```

See [`warden/cloaking/README.md`](../warden/cloaking/README.md) for full implementation details.
