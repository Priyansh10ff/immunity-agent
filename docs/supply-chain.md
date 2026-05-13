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
| Has postinstall/preinstall script | +20 |
| Single maintainer | +10 |
| Custom `--registry` flag | +10 |
| Local path dependency | +10 |
| Maintainer data unavailable | +8 |

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

**mini-shai-hulud - May 11, 2026** (attribution: TeamPCP)

GitHub Actions pwn-request against `TanStack/router` triggered a `pull_request_target` workflow with base repository permissions. The attacker poisoned the pnpm cache (1.1 GB entry) via malicious commit `79ac49ee`, extracted OIDC tokens directly from runner memory, then published backdoored packages with valid SLSA Build Level 3 attestations.

Affected packages (170+ total):

| Package | Ecosystem | Compromised versions |
|---|---|---|
| `@tanstack/*` | npm | all versions published May 11 2026 (42 packages) |
| `@opensearch-project/*` | npm | all versions published May 11 2026 |
| `@uipath/*` | npm | all versions published May 11 2026 (65 packages) |
| `@mistralai/mistralai` | npm | 1.7.1 - 2.2.4 |
| `mistralai` | PyPI | 2.4.6 (legitimate latest: 2.4.5) |
| `guardrails-ai` | PyPI | 0.10.1 (legitimate latest: 0.10.0) |

npm delivery: `preinstall` hook runs `setup.mjs`, downloads Bun runtime, executes `router_init.js` / `tanstack_runner.js` via `optionalDependencies` pointing to malicious GitHub commits.

PyPI delivery: payload injected into `__init__.py`, downloads `/tmp/transformers.pyz` on import.

Credential targets: GitHub tokens (`ghp_*`, `gho_*`, `ghs_*`), npm publish tokens (`npm_*`), AWS IAM (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), AWS instance metadata (`169.254.169.254`), HashiCorp Vault (`127.0.0.1:8200`), Kubernetes service accounts.

C2 infrastructure: `filev2.getsession.org` (Session Protocol exfiltration), `git-tanstack.com` (phishing domain, Cloudflare-flagged). Secondary C2 via GitHub GraphQL - encodes instructions in commit messages, exfiltrates via repo contents API.

Worm propagation: uses `createCommitOnBranch` GraphQL mutation to commit poisoned `.vscode/setup.mjs` and `.claude/setup.mjs` to feature branches, spreading to other developers who pull the branch.

Persistence: `.claude/settings.json`, `.claude/setup.mjs`, `.claude/router_runtime.js`, `.vscode/tasks.json`, `.vscode/setup.mjs`

Known payload hashes (SHA-256):
- `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` - `router_init.js`
- `ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01` - `tanstack_runner.js`

> Valid SLSA Build Level 3 attestations do **not** protect against this attack. The attacker held legitimate OIDC tokens at publish time. This is the first documented npm worm to produce valid SLSA attestations. Same threat actor (TeamPCP) was responsible for the March 2026 Trivy supply chain compromise.

References: [Prismor](https://prismor.dev/blog/tanstack-mistral-mini-shai-hulud-supply-chain) - [Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised/) - [SafeDep](https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/)

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
