---
name: code-security
version: 1.0.0
description: Security guidelines for writing secure code. Use when writing code, reviewing code for vulnerabilities, or asking about secure coding practices like "check for SQL injection" or "review security".
homepage: https://github.com/PrismorSec/prismor
metadata: {"openclaw":{"emoji":"🔒","category":"security"}}
attribution: Curated and enhanced for Prismor, structured around the OWASP Top 10.
---

# Code Security Guidelines

Comprehensive security rules for writing secure code across multiple languages and frameworks. Covers OWASP Top 10 vulnerabilities, infrastructure security, and coding best practices.

> **Note:** These rules are curated and enhanced for Prismor, and structured around the [OWASP Top 10](https://owasp.org/www-project-top-ten/).

## How to Use This Skill

1. When you write or review code, reference these security guidelines to catch vulnerabilities before they ship.
2. Each rule file includes incorrect (vulnerable) and correct (secure) code patterns across multiple languages.
3. Rules are organized by vulnerability category and impact level.
4. When a user asks you to "review security", "check for vulnerabilities", or write code touching databases, file systems, or external input — automatically consult the relevant rules below.

## Rule Directories

Reference the specific rule files for detailed language examples:

| File | Rule | Impact |
|------|------|--------|
| `rules/sql-injection.md` | SQL Injection prevention | CRITICAL |
| `rules/command-injection.md` | Command Injection prevention | CRITICAL |
| `rules/xss.md` | Cross-Site Scripting prevention | CRITICAL |
| `rules/path-traversal.md` | Path Traversal prevention | CRITICAL |
| `rules/secrets.md` | Hardcoded Secrets prevention | CRITICAL |
| `rules/xxe.md` | XXE Injection prevention | CRITICAL |
| `rules/insecure-deserialization.md` | Insecure Deserialization prevention | CRITICAL |
| `rules/code-injection.md` | Code Injection (eval/exec) prevention | CRITICAL |
| `rules/memory-safety.md` | Memory Safety (C/C++) rules | CRITICAL |
| `rules/insecure-crypto.md` | Insecure Cryptography prevention | HIGH |
| `rules/ssrf.md` | Server-Side Request Forgery prevention | HIGH |
| `rules/insecure-transport.md` | Insecure Transport prevention | HIGH |
| `rules/authentication-jwt.md` | Secure JWT Authentication | HIGH |
| `rules/csrf.md` | CSRF prevention | HIGH |
| `rules/prototype-pollution.md` | Prototype Pollution prevention | HIGH |
| `rules/unsafe-functions.md` | Unsafe Function Avoidance | HIGH |
| `rules/terraform-aws.md` | AWS Terraform security | HIGH |
| `rules/terraform-azure.md` | Azure Terraform security | HIGH |
| `rules/terraform-gcp.md` | GCP Terraform security | HIGH |
| `rules/kubernetes.md` | Kubernetes Manifest security | HIGH |
| `rules/docker.md` | Dockerfile security | HIGH |
| `rules/github-actions.md` | GitHub Actions security | HIGH |

## Categories

### Critical Impact

- **SQL Injection** — Use parameterized queries, never concatenate user input into SQL strings
- **Command Injection** — Avoid shell=True or string-concatenated system calls; use array-form exec APIs
- **XSS** — Escape all output; use framework-provided escaping utilities
- **Path Traversal** — Validate and sanitize file paths; reject paths containing `..`
- **Hardcoded Secrets** — Use environment variables or secret managers, never hardcode credentials

### High Impact

- **Insecure Crypto** — Use SHA-256+, AES-256-GCM; avoid MD5, SHA1, DES, ECB
- **Insecure Transport** — Enforce HTTPS, verify TLS certificates, disable SSLv2/3
- **SSRF** — Validate URLs against an allowlist before making outbound requests
- **JWT Issues** — Always verify signatures; never use `alg: none`
- **CSRF** — Use CSRF tokens on every state-changing request

## Quick Reference

| Vulnerability | Key Prevention |
|--------------|----------------|
| SQL Injection | Parameterized queries / prepared statements |
| XSS | Output encoding, Content-Security-Policy |
| Command Injection | Avoid shell, use array-form exec APIs |
| Path Traversal | Validate & canonicalize paths |
| SSRF | URL allowlists, block internal ranges |
| Secrets | Environment variables / secret managers |
| Crypto | SHA-256, AES-256-GCM |

## Agent Instructions

When reviewing or writing code, automatically apply these checks:

1. **Database queries** → Read `rules/sql-injection.md`
2. **System/shell calls** → Read `rules/command-injection.md`
3. **HTML output or templates** → Read `rules/xss.md`
4. **File path handling** → Read `rules/path-traversal.md`
5. **Credentials or tokens in code** → Read `rules/secrets.md`
6. **XML parsing** → Read `rules/xxe.md`
7. **Object deserialization** → Read `rules/insecure-deserialization.md`
8. **Dynamic code execution (eval/exec)** → Read `rules/code-injection.md`
9. **C/C++ memory management** → Read `rules/memory-safety.md`
10. **Cryptographic operations** → Read `rules/insecure-crypto.md`
11. **Outbound HTTP calls** → Read `rules/ssrf.md`
12. **HTTP/TLS configuration** → Read `rules/insecure-transport.md`
13. **JWT handling** → Read `rules/authentication-jwt.md`
14. **Web forms and state changes** → Read `rules/csrf.md`
15. **JavaScript object merging** → Read `rules/prototype-pollution.md`
16. **Using libc or low-level functions** → Read `rules/unsafe-functions.md`
17. **AWS Terraform files** → Read `rules/terraform-aws.md`
18. **Azure Terraform files** → Read `rules/terraform-azure.md`
19. **GCP Terraform files** → Read `rules/terraform-gcp.md`
20. **Kubernetes manifests** → Read `rules/kubernetes.md`
21. **Dockerfiles** → Read `rules/docker.md`
22. **GitHub Actions workflows** → Read `rules/github-actions.md`

If a vulnerability is detected, report it with:
- **Severity level** (CRITICAL / HIGH / MEDIUM)
- **CWE reference** where applicable
- **Specific line or pattern** that is vulnerable
- **Recommended fix** with a code example from the relevant rule file

## References

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Prismor](https://github.com/PrismorSec/prismor)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
