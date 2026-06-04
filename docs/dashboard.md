# Dashboard & Sessions

Warden logs every agent tool call — not just the ones it blocks — to a local
SQLite store. This doc covers the three ways to read that history: the
**terminal dashboard**, the **local web dashboard**, and the **session**
commands for drilling into a single run.

Everything is local. `serve` binds to `127.0.0.1` by default; there is no cloud
component and no external service.

Implementation: [`warden/server.py`](../warden/server.py), session store in
[`warden/store.py`](../warden/store.py).

---

## Where the data lives

```
.prismor-warden/
├─ sessions/<session-id>.jsonl   append-only log, one JSON object per tool call
└─ warden.db                     SQLite, indexed for cross-session queries
```

Workspaces are registered as you install hooks, so the dashboards can aggregate
across every project you've protected.

```
   workspace A ─┐
   workspace B ─┼─► registered workspaces ─► dashboard / serve ─► you
   workspace C ─┘        (warden.db each)
```

---

## Terminal: `immunity status` and `immunity dashboard`

```bash
immunity status        # THIS workspace: hooks, mode, cloak, latest session, next step
immunity dashboard     # ALL workspaces: risk, findings, mode, last activity
```

- **`status`** is the per-workspace health check — run it first every session. It
  ends with the single next action that matters (install hooks, switch to
  enforce, review findings, or "clean").
- **`dashboard`** is the cross-project bird's-eye view: one line per registered
  workspace with its latest risk score, finding count, mode, and how long ago it
  was active.

---

## Web: `immunity serve`

```bash
immunity serve                       # http://127.0.0.1:7070
immunity serve --port 8080           # custom port
immunity serve --host 127.0.0.1      # bind host (keep it local)
```

Serves a self-contained HTML dashboard plus a small JSON API over the registered
workspace databases. The only external resource is a Chart.js CDN link loaded by
the browser; the data never leaves your machine.

| Endpoint | Returns |
|---|---|
| `GET /` | The HTML dashboard |
| `GET /health` | `{"status": "ok", "ts": …}` |
| `GET /api/stats` | Aggregate stats for the KPIs / charts |
| `GET /api/sessions` | Paginated sessions (`?page&limit&sort&dir`) |
| `GET /api/findings` | Paginated findings (`?page&limit&agent&severity&category&q`) |
| `GET /api/events` | Paginated events (`?page&limit&verdict&agent`) |
| `GET /api/supply-chain` | Supply-chain enforcement stats |

If you run `serve` before installing hooks anywhere, it warns that no workspaces
are registered yet — install hooks in a project first to collect data.

---

## Drilling in: `sessions` and `session`

```bash
immunity sessions                          # recent sessions, this workspace
immunity sessions --findings-only          # only flagged runs, sorted by risk
immunity sessions --findings-only --global # flagged runs across all workspaces
immunity sessions --limit 50 --json        # machine-readable

immunity session <id>                      # full trace + findings for one session
immunity session <id> --json
```

Every shell command, file read/write, web fetch, and user prompt is captured, so
`immunity session <id>` is your forensic timeline for a specific incident — what
the agent did, in order, and which findings fired.

---

## Offline analysis: `analyze` and `ingest`

For CI gating or replaying an old trace against a newer policy:

```bash
immunity analyze                       # analyze the most recent session
immunity analyze --input session.jsonl # analyze a specific JSONL log
immunity analyze --sarif               # SARIF 2.1.0 for GitHub Code Scanning
immunity ingest --input session.jsonl  # analyze AND store in the DB
```

`--sarif` output drops straight into GitHub Code Scanning or the VS Code SARIF
viewer, with full rule metadata.

---

## See also

- [Warden](warden.md) — session-log schema and the audit command
- [Learning](learning.md) — mines this same history for new rules
- [CLI Reference](cli-reference.md) — all commands at a glance
