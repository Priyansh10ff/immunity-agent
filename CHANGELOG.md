# Changelog

All notable changes to Immunity Agent (Prismor Warden) are documented here.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.4.0] — 2026-05-12

Supply Chain Enforcement — `immunity` CLI. Intercepts package manager install
commands before execution, scores each package against live threat intelligence,
and blocks or warns based on risk signals. Ships with IOC coverage for the
mini-shai-hulud attack (May 11 2026) out of the box.

### Added

- **`immunity` CLI wrapper** — shebang script at repo root intercepts
  `npm/pip/pnpm/uv/cargo/go install` commands before execution.
- **`supplychain/ecosystems/detector.py`** — parses install argv into a
  structured `InstallEvent` across 9 ecosystems.
- **`supplychain/ecosystems/metadata.py`** — fetches npm and PyPI registry
  metadata (age, maintainers, install scripts); stdlib only, fail-open.
- **`supplychain/scoring/engine.py`** — additive signal scorer producing
  allow/warn/block verdicts.
- **`supplychain/ioc.py`** — IOC database covering `@tanstack/*`,
  `@mistralai/mistralai` 1.7.1–2.2.4, C2 domains (`getsession.org`,
  `masscan.cloud`), and install script patterns (Bun download,
  `router_init.js`, credential env var access, persistence writes).
- **`docs/supply-chain.md`** — full documentation: usage, scoring table,
  ecosystem support, IOC advisory for mini-shai-hulud, guide for adding new
  IOCs, internal architecture.

## [1.3.0] — 2026-05-11

Web Dashboard — `warden serve`. Introduces a local HTTP API server and
self-contained browser dashboard that aggregates session, findings, and event
data from all registered workspaces.

### Added

- **`warden serve` command** (`warden/server.py`, `warden/dashboard.html`).
  Starts a local HTTP server (default `127.0.0.1:7070`) serving a
  self-contained Prismor Warden dashboard. Accepts `--host` and `--port` flags.
- **Dashboard UI** with severity breakdown strip (critical/high/medium/low
  counts), recent sessions table with risk-score bars, and a findings drilldown
  with agent/severity/category filters, free-text search, and expandable
  evidence rows showing raw command/path and session ID.
- **Server-side pagination** for sessions (`/api/sessions`), findings
  (`/api/findings`), and events (`/api/events`) — each endpoint accepts
  `page`, `limit`, sort, and filter query params; returns
  `{items, total, page, pages, limit}`.
- **Live event feed** with verdict (blocked/allowed) and agent filter controls;
  auto-poll pauses when user has active filters or is past page 1.
- **`get_sessions_page()`, `get_findings_page()`, `get_events_page()`** added
  to `warden/store.py`; `get_aggregate_stats()` extended with
  `severityBreakdown`, `recentSessions`, and `recentFindings`.

### Fixed

- **XSS prevention in dashboard**: replaced all `innerHTML` string
  concatenation with a `safe()` helper that text-encodes untrusted values
  before inserting them into the DOM.

## [1.2.0] — 2026-04-27

Tier 3 — Scoped Agent and Session-Based Learning. Adds per-session rule
synthesis via the Anthropic API, a session-based learning engine that mines
uncovered command patterns and detects evasion attempts, and five security
and correctness fixes from code review.

### Added

- **Scoped Agent** (`warden/scoped_agent.py`). On `UserPromptSubmit`, Warden
  calls the Anthropic API (Haiku) to synthesise a minimal, task-specific rule
  set from the user's goal — restricting tools, file paths, and network access
  to only what the task genuinely requires. Falls back to keyword-based static
  heuristics when no API key is present. Scoped rules are stored as JSON
  sidecar files in `.prismor-warden/scoped/` and enforced alongside
  `policy.yaml` for the duration of that session only.
- **Session-Based Learning** (`warden/learning.py`). Mines historical session
  data for recurring uncovered command patterns, tracks false positives from
  dismissed findings, and detects evasion attempts where structurally similar
  commands (e.g. backtick vs `$()` substitution) bypass existing rules.
  Candidate rules can be reviewed and promoted to `policy.yaml`.
- **`warden scope` subcommands** — `show`, `list`, `edit`, `clear` for
  inspecting and managing active scoped sessions.
- **`warden learn` subcommands** — `--json`, `--apply`, `--reject`,
  `--candidates` for reviewing and acting on mined rule proposals.
- **Evasion detection** — shell commands that pass policy but are structurally
  similar (Jaccard ≥ 0.6 after substitution normalisation) to a recently
  blocked command in the same session are flagged as `HIGH` findings.
- **Dismissal tracking** — in observe mode, dismissed findings are recorded
  in the database and surfaced via `warden learn` as false-positive candidates.

### Fixed

- **Prompt-injection mitigation in scoped rule synthesis**: LLM-returned
  `allowed_tools` and `deny_tools` are now clamped to the known-good
  `available_tools` list, preventing a crafted task prompt from expanding the
  scoped policy beyond what the agent actually has access to.
- **Command injection in `warden scope edit`**: replaced
  `os.system(f'{editor} "{path}"')` with `subprocess.run([editor, path])`
  to prevent shell metacharacter exploitation via the `$EDITOR` env var.
- **`KeyError: 'id'` in `warden learn` output**: `format_learning_report`
  now uses `c.get('id', c['rule'].get('id', '?'))` so freshly-mined
  candidates (not yet persisted to the DB) display correctly.
- **Misleading scoped-rules display text**: the rules box now correctly states
  that rules persist in `.prismor-warden/scoped/` rather than claiming they
  are not saved.
- **Removed dead `get_scoped_dir()` from `warden/store.py`**: the function
  was unreachable and pointed to a different path than `scoped_agent._scoped_dir`.

## [1.1.0] — 2026-04-24

Tier 1 coverage expansion from `IMPROVEMENT_PLAN.md` — focused on closing
audit-level detection gaps and adding the developer- and SIEM-facing
ergonomics features enterprise buyers expect. Continues from `1.0.2`.

### Added

- **Canarytoken subsystem** (`warden canary plant|list|remove|status`). Plant
  realistic fake credentials (AWS, SSH, `.env`, generic) at arbitrary paths;
  any read raises a `CRITICAL` finding and optionally POSTs a signed payload
  to a user-provided webhook. First AI-agent-specific canarytoken
  implementation we're aware of. (`warden/canary.py`)
- **MCP schema auditor** — `warden scan` now statically analyses MCP tool
  schemas for over-broad allowlists (`"*"`, `"/**"`), risky description
  language (`bypass`, `all files`, `sudo`), `any`-typed parameters on
  execution-capable tools, missing input schemas, and servers that combine
  execution with filesystem + network access in a single surface.
  (`warden/scanner.py::audit_mcp_schema`)
- **Lockfile integrity audit** — `warden deps` now detects non-registry
  sources (`git+`, `file:`) in `package-lock.json`, missing `integrity:`
  hashes, and lockfile-injection (direct deps in the lockfile that aren't
  declared in `package.json`). (`warden/deps.py::check_lockfile_integrity`)
- **Agent instruction-file tamper detection** — new `agent-instruction-tampering`
  rule covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`,
  `.github/copilot-instructions.md`. Previously only `.claude/settings.json`
  was protected. (`warden/default_policy.yaml`)
- **Unicode / homoglyph path detection** — flags paths and commands that mix
  ASCII letters with Cyrillic, Greek, Latin-extended confusables, fullwidth
  letters, and zero-width joiners (e.g. `cat .еnv` where `е` is U+0435).
  (`warden/policy_engine.py::_has_suspicious_unicode`)
- **Telemetry sinks** — new `settings.outputs` section in `policy.yaml`
  forwards findings to webhook, syslog (UDP/TCP), and file sinks. File sink
  supports both JSON and ArcSight CEF formats for SIEM ingest. Env-var
  interpolation (`${SIEM_TOKEN}`) for secret headers. (`warden/sinks.py`)
- **Declarative policy tests** — `warden policy test` runs
  `.prismor-warden/policy-tests.yaml` cases (`{input, expect: block|warn|pass}`)
  and ships a bundled OWASP LLM Top 10 + Agentic Top 10 + MITRE ATLAS
  starter pack (28 cases). (`warden/policy_test.py`,
  `templates/policy-tests-owasp.yaml`)
- **`warden check --explain`** — shows matched rule's category, action,
  event types, field list, and full regex pattern.
- **`warden check --from-log PATH`** — replay a JSONL session log through the
  current policy to validate rule changes.
- **`warden check --suggest-allowlist`** — emits a ready-to-paste
  `allowlists:` entry when a command triggers a finding the user considers
  intentional.

### Changed

- **Destructive-command rule** now accepts positional arguments with
  optional quotes (`rm -rf "/etc"`), catches separate flags (`rm -r -f /`)
  and long-form (`rm --recursive --force /`), while still passing safe
  cleanup (`rm -rf ./node_modules`, `rm -rf /tmp/build`, `rm -rf ../build`).
- **Reverse-shell rule** catches `nc -lvp 4444 -e /bin/bash` (combined
  listen+port flag) in addition to the separate `-l` / `-p` form.
- **`/dev/tcp/<host>`** now matches any hostname, not just dotted-quad IPs.
- **TLS verification bypass** rule extended: `git -c http.sslVerify=false`
  inline override, `curl -sk` / `-ksL` / `-Lk` combined flags.
- **npm supply-chain** rules: `--registry` flag matched regardless of
  position (before or after `install|i|add`); yarn/pnpm parity.
- **Shell-obfuscation** rule now matches `perl pack(q{H*}, …)` alternate
  Perl quoting forms in addition to classic `pack("H*", …)`.

### Infrastructure

- `warden deps` now prints a dedicated "Lockfile integrity issues"
  section and exits `1` when a HIGH-severity integrity issue is present.
- `warden canary remove` by id or path; `warden canary status` summarises
  registered canaries by type.
- `warden hook-dispatch` now invokes telemetry sinks BEFORE the blocking
  decision so SIEMs see every event, including blocked ones.

### Tests

- 227 unit tests, all passing (no regression since 0.2.0).
- 28/28 OWASP starter policy-test cases pass on a clean install.
- Lightsail regression matrix: 97/97 adversarial and golden-path cases
  green (same matrix that validated PR #19).

## [0.2.0] — 2026-04-21

First comprehensive audit-fix release — see PR #19 in the GitHub repo for
details. Closes 15 detection/lifecycle gaps identified by external review
plus six adversarial bypass variations surfaced during variation testing.
