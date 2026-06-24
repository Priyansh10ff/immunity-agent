# Prismor Security — CLAUDE.md

This project is the Prismor security package for AI coding agents.

## Warden Runtime Protection

This repo has Warden hooks enabled. The hook dispatcher at `warden/cli.py` monitors tool calls and blocks dangerous actions in real time.

## Cloaking (secret prevention)

The `warden/cloaking/` subsystem is Prismor's prevention layer for secret leaks. Real secret values live under `~/.prismor/secrets/` and are referenced in tool calls as `@@SECRET:<name>@@`. When editing this subsystem, treat it as security-sensitive code and never print, log, or narrate real secret values — use the placeholder form in all examples and prose. See [`warden/cloaking/README.md`](./warden/cloaking/README.md) for the full design and [`AGENTS.md`](./AGENTS.md#cloaking-secret-prevention-layer) for editing guidelines.

## Working in This Repo

- The `advisories/` directory contains the signed threat feed — do not manually edit it. Use the pipeline scripts.
- The `warden/` directory is the runtime policy engine. Changes to `policies.py` affect what gets blocked in enforce mode.
- The `pipeline/` directory contains the NVD fetch/merge/sign automation. The schema at `pipeline/schemas/threat-object.schema.json` is the source of truth for feed structure.
- Run `python3 scripts/upgrade_feed.py` after pipeline changes to retroactively improve existing advisories.
- Run `bash scripts/verify_feed.sh` to verify feed signature integrity.
- Public key for signature verification is at `keys/public.pub`.
