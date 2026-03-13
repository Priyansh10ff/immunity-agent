# Prismor Security — CLAUDE.md

This project is the Prismor security package for AI coding agents.

## Security Skills (load at session start)

Read `skills/security.md` and follow its instructions. This is the single entry point that loads:
- Behavioral guardrails (deny-listed commands, secret protection, anti-prompt-injection)
- Live threat intelligence feed integration
- Secure coding rules (OWASP Top 10, infrastructure, CI/CD)
- LLM security rules (OWASP Top 10 for LLMs)

## Warden Runtime Protection

This repo has Warden hooks enabled. The hook dispatcher at `warden/cli.py` monitors tool calls and blocks dangerous actions in real time.

## Working in This Repo

- The `advisories/` directory contains the signed threat feed — do not manually edit it. Use the pipeline scripts.
- The `skills/` directory contains agent-readable security rules. Treat changes to skills as product-level changes — test for accuracy and actionability.
- The `warden/` directory is the runtime policy engine. Changes to `policies.py` affect what gets blocked in enforce mode.
- The `pipeline/` directory contains the NVD fetch/merge/sign automation. The schema at `pipeline/schemas/threat-object.schema.json` is the source of truth for feed structure.
- Run `python3 scripts/upgrade_feed.py` after pipeline changes to retroactively improve existing advisories.
- Run `bash scripts/verify_feed.sh` to verify feed signature integrity.
- Public key for signature verification is at `keys/public.pub`.
