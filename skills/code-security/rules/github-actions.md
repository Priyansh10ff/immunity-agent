---
title: Secure GitHub Actions
impact: HIGH
impactDescription: Compromised CI/CD pipelines lead to supply chain attacks and unauthorized code deployment
tags: security, github-actions, cicd, supply-chain, yaml
attribution: Curated and enhanced for Prismor
---

## Secure GitHub Actions

GitHub Actions security focuses on preventing unauthorized access to secrets, stopping code injection in workflows, and ensuring third-party actions are trusted.

---

### Prevent Script Injection via Contexts

Using untrusted input (like issue titles or PR branch names) in scripts allows code injection.

**Incorrect:**
```yaml
- name: Log message
  run: |
    echo "Processing issue: ${{ github.event.issue.title }}" # VULNERABLE: Title can contain $(whoami)
```

**Correct (use environment variables):**
```yaml
- id: log
  run: |
    echo "Processing issue: $TITLE"
  env:
    TITLE: ${{ github.event.issue.title }} # Safe: Bash handles as data
```

---

### Pin Actions to Full SHA

Tag names (v1) and branch names (main) can be moved by action authors. Shas are immutable.

**Incorrect:**
```yaml
- uses: actions/checkout@v3  # VULNERABLE: tag can be hijacked
```

**Correct:**
```yaml
- uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2
```

---

### Restrict GITHUB_TOKEN Permissions

By default, the `GITHUB_TOKEN` may have excessive permissions (read/write).

**Incorrect:**
```yaml
# Use default permissions (can be dangerous)
```

**Correct (Principle of Least Privilege):**
```yaml
permissions:
  contents: read
  issues: write
```

---

## Key Prevention Rules

1. **Use environment variables for secrets/contexts** — Never interpolate `${{ }}` directly into shell scripts.
2. **Pin by SHA** — Use the immutable commit hash for all third-party actions.
3. **Minimize `GITHUB_TOKEN` scope** — Define a `permissions` block in every workflow.
4. **No secrets in logs** — Use masking `echo "::add-mask::$SECRET"` if necessary, but prefer GitHub's automatic secret masking.
5. **Review third-party actions** — Regularly audit the actions you use for security updates or malicious changes.

**References:**
- [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Prismor](https://github.com/PrismorSec/prismor)
