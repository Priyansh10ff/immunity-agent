# Using Cloak — secret protection in practice

Cloak keeps real secret values out of the model's context, the transcript, and
the upstream API. You work with placeholders (`@@SECRET:name@@`); the real value
only exists inside the local hook process at execution time.

This is the practical guide. For internals see
[`warden/cloaking/README.md`](../warden/cloaking/README.md).

## Setup (once)

Two layers. Install both — they're complementary:

```bash
immunity cloak install                                  # prevention: cloak secrets at the tool boundary
immunity install-hooks --agent claude --mode enforce    # enforcement: block direct reads of the vault
```

Cloak alone keeps secrets out of context. The runtime monitor is what stops an
agent from simply opening the vault files (see *Threat model* below) — so you
want both.

## Everyday use

You mostly do nothing. The flow is automatic:

- **Paste a secret into chat** → it's detected, vaulted, and your prompt is
  blocked once so you resubmit the sanitized version. From then on the model
  sees only `@@SECRET:auto_xxxx@@`.
- **The model emits a raw secret in a command, file, or MCP call** → the call is
  denied, the value is vaulted, and the model is told to use the placeholder.
- **The model uses a placeholder** → the hook substitutes the real value at run
  time and scrubs it back out of the output.

Register a secret deliberately (value read from stdin, never argv):

```bash
immunity cloak add stripe_key      # then reference it anywhere as @@SECRET:stripe_key@@
immunity cloak list                # placeholder names only — never values
```

## Custom detection patterns

Built-in patterns cover Stripe, GitHub, AWS, Google, Slack, GitLab, and JWTs.
Add your org's token formats:

```bash
immunity cloak pattern add 'mycorp_[0-9a-f]{32}'
```

Patterns are POSIX regex, validated on add, and apply to both the paste guard
and the tool-call guard.

## Best practices

- **Run both layers.** `cloak install` without the enforce-mode monitor leaves
  the vault readable by a determined or prompt-injected agent.
- **Reference, never inline.** Use `@@SECRET:name@@` in commands and files. Don't
  ask the model to hardcode a live secret into a file — store the placeholder or
  an env-var reference instead.
- **Protect the vault directory.** `~/.prismor/secrets/` is plaintext on disk
  (file permissions are its only guard). Exclude it from git, backups, and sync
  (Time Machine, iCloud, Dropbox). Add a Claude `permissions.deny` rule for
  `Read(~/.prismor/secrets/**)` for defense in depth.
- **`/clear` after any suspected leak.** If the model ever saw a raw value, it
  can still echo it from memory — hooks can't filter assistant prose.
- **Don't fight a false positive — bypass it.** Prefix a prompt with `!!allow `
  to discuss a secret format without auto-cloaking.

## Threat model — what it does and doesn't cover

| Scenario | Covered? |
|---|---|
| Secret in a pasted prompt | ✅ auto-vaulted, prompt re-sanitized |
| Raw secret in a command / file write / MCP arg | ✅ denied + vaulted |
| Model using a placeholder | ✅ resolved locally, output scrubbed |
| Agent directly reading a vault file | ✅ **only with the enforce-mode monitor** |
| Secret with no recognizable shape (hand-typed, freshly generated) | ⚠️ may not match a pattern |
| Model narrating a value it already saw | ❌ use `/clear` |
| Anything running as your user, off-agent | ❌ OS file permissions only |

Bottom line: in normal placeholder-based use with both layers installed, the AI
never sees vault contents. The vault is not encrypted at rest, so the protection
against a *direct read* is the runtime monitor and your file permissions — not
the cloaking hooks alone.
