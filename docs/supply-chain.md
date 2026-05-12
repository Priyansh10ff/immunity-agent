# Supply Chain Enforcement

Immunity Agent wraps your package manager so every install is evaluated before it runs. The `immunity` CLI intercepts the command, scores each package against live threat intelligence, then either passes through to the real package manager or blocks with a reason.

---

## Usage

```bash
immunity npm install express
immunity pip install requests numpy
immunity pnpm add lodash
immunity uv add fastapi
immunity cargo add serde
immunity go get github.com/some/pkg
```

Any command that isn't a recognised package install passes through transparently - so you can alias `npm` or `pip` to `immunity` without breakage.

```bash
# Alias-based transparent wrapping
alias npm="python3 /path/to/immunity-agent/immunity npm"
alias pip="python3 /path/to/immunity-agent/immunity pip"
```

---

## Output

```
  IMMUNITY  supply chain  [npm]
  ────────────────────────────────────────────────────

  BLOCK  score 100  @tanstack/react-router  age 1d, 3 maintainers
             +100 @tanstack/* - 42 packages compromised May 11 2026 via CI/CD cache
                  poisoning. SLSA attestations do NOT protect against this.
             +100 known malicious payload referenced: router_init.js
             +50  Bun runtime execution in install script

  WARN   score  35  github:user/pkg
             +35 git/GitHub dependency bypasses registry

  ALLOW  score   0  express  age 5612d, 5 maintainers

  Blocked: @tanstack/react-router
  To override: add to supply_chain.allowlist in .prismor-warden/policy.yaml
```

---

## Scoring

Each package is scored additively. IOC matches bypass the threshold and force a block regardless of total score.

| Signal | Points |
|---|---|
| Known compromised package / IOC match | +100 (force block) |
| C2 domain in install script | +100 (force block) |
| Known malicious payload in install script | +100 (force block) |
| Bun runtime download in install script | +100 (force block) |
| Credential env var access in install script (`AWS_SECRET`, `GITHUB_TOKEN`, etc.) | +50 |
| Persistence write in install script (`.claude/settings.json`, `.vscode/tasks.json`) | +50 |
| git / GitHub dependency bypasses registry | +35 |
| tarball install bypasses registry | +25 |
| Package published < 7 days ago | +25 |
| Package published < 30 days ago | +15 |
| Single maintainer | +10 |
| Custom `--registry` flag | +10 |
| Local path dependency | +10 |

**Verdicts:** `< 30` allow · `30–59` warn · `≥ 60` block

---

## Supported Ecosystems

| Ecosystem | Commands intercepted |
|---|---|
| npm | `npm install`, `npm i`, `npm add` |
| pnpm | `pnpm install`, `pnpm add`, `pnpm i` |
| yarn | `yarn add` |
| bun | `bun add`, `bun install` |
| pip | `pip install`, `pip3 install` |
| uv | `uv add`, `uv pip install` |
| poetry | `poetry add` |
| cargo | `cargo add`, `cargo install` |
| go | `go get`, `go install` |

---

## Threat Intelligence

The IOC database lives in [`supplychain/ioc.py`](../supplychain/ioc.py). It is checked before any registry call - IOC matches are immediate, not scored.

### Active advisories

**mini-shai-hulud - May 11, 2026**

GitHub Actions pwn-request against `TanStack/router` triggered a `pull_request_target` workflow with base repository permissions. The attacker poisoned the pnpm cache (1.1 GB entry) and extracted OIDC tokens directly from the runner's memory, then used them to publish backdoored packages with valid SLSA Build Level 3 attestations.

Affected packages:
- `@tanstack/*` - 42 packages, 84 versions (all published May 11 2026)
- `@mistralai/mistralai` - versions 1.7.1–2.2.4

Payload: 2.3 MB Bun-based credential harvester (`router_init.js`, SHA-256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`). Targets GitHub Actions secrets, AWS credentials, Kubernetes service accounts, and AI developer tool configs.

C2 infrastructure: `*.getsession.org` (Session Protocol), `api.masscan.cloud`

Persistence: `.claude/settings.json`, `.vscode/tasks.json`, system deadman's switch service

> Note: Valid SLSA Build Level 3 attestations do **not** protect against this attack. The attacker held legitimate OIDC tokens at publish time, so provenance signatures are cryptographically valid but meaningless. This is the first documented npm worm to produce valid SLSA attestations.

References: [Prismor blog](https://prismor.dev/blog/tanstack-mistral-mini-shai-hulud-supply-chain) · [Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised/)

---

### Adding new IOCs

Open [`supplychain/ioc.py`](../supplychain/ioc.py) and add to the relevant section:

```python
# Compromised package version range
_COMPROMISED_VERSIONS["@scope/package"] = [
    {
        "min": "1.0.0", "max": "1.2.3",
        "attack": "attack-id-YYYY-MM-DD",
        "note": "brief description with reference",
    }
]

# Compromised namespace
_COMPROMISED_NAMESPACES["@scope/"] = {
    "attack": "attack-id-YYYY-MM-DD",
    "affected_date": "YYYY-MM-DD",
    "note": "brief description",
}

# C2 domain
C2_DOMAINS |= {"evil.example.com"}

# Install script pattern
_SCRIPT_PATTERNS.append((
    re.compile(r"evil\.example\.com", re.I),
    "C2 domain: evil.example.com",
    "CRITICAL",
))
```

---

## Architecture

```
immunity npm install express
         │
         ▼
supplychain/ecosystems/detector.py   - parse argv → InstallEvent
         │
         ▼
supplychain/ecosystems/metadata.py   - fetch registry metadata (npm / PyPI)
         │                             3s timeout, fail-open, 5-min cache
         ▼
supplychain/ioc.py                   - IOC check (package versions, namespaces)
         │                             check install script content for C2/patterns
         ▼
supplychain/scoring/engine.py        - additive signal scoring → allow/warn/block
         │
    ┌────┴─────┐
  block      allow/warn
    │              │
  exit 1      os.execv(npm, argv)   - replace process, transparent passthrough
```

The `immunity` binary at the repo root is a thin shebang wrapper over `supplychain/cli.py`. Non-install commands (`npm run build`, `pip freeze`, etc.) skip evaluation entirely and exec directly.
