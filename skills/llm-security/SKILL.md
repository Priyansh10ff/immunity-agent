---
name: llm-security
version: 1.0.0
description: Security guidelines for LLM applications based on OWASP Top 10 for LLM 2025. Use when building LLM apps, reviewing AI security, implementing RAG systems, or asking about LLM vulnerabilities like "prompt injection" or "check LLM security".
homepage: https://github.com/prismorsec/immunity-agent
metadata: {"openclaw":{"emoji":"🤖","category":"security"}}
attribution: Curated and enhanced for Prismor, structured around the OWASP Top 10 for LLM applications.
---

# LLM Security Guidelines (OWASP Top 10 for LLM 2025)

Comprehensive security rules for building secure LLM applications. Based on the OWASP Top 10 for Large Language Model Applications 2025 — the authoritative guide to LLM security risks.

> **Note:** These rules are curated and enhanced for Prismor, and structured around the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).

## How to Use This Skill

1. When building or reviewing LLM applications, reference these security guidelines automatically.
2. Each rule file includes vulnerable patterns and secure implementations.
3. Rules cover the complete LLM application lifecycle: training, deployment, and inference.
4. When a user asks about "prompt injection", "LLM security", "RAG security", or "AI agent security" — consult the relevant rules below.

## Rule Directories

| File | Vulnerability | Impact |
|------|--------------|--------|
| `rules/prompt-injection.md` | LLM01: Prompt Injection | CRITICAL |
| `rules/sensitive-disclosure.md` | LLM02: Sensitive Information Disclosure | CRITICAL |
| `rules/supply-chain.md` | LLM03: Supply Chain | CRITICAL |
| `rules/data-poisoning.md` | LLM04: Data and Model Poisoning | CRITICAL |
| `rules/output-handling.md` | LLM05: Improper Output Handling | CRITICAL |
| `rules/excessive-agency.md` | LLM06: Excessive Agency | HIGH |
| `rules/system-prompt-leakage.md` | LLM07: System Prompt Leakage | HIGH |
| `rules/vector-embedding.md` | LLM08: Vector and Embedding Weaknesses | HIGH |
| `rules/misinformation.md` | LLM09: Misinformation | MEDIUM |
| `rules/unbounded-consumption.md` | LLM10: Unbounded Consumption | HIGH |

## Categories

### Critical Impact

- **LLM01: Prompt Injection** — Validate inputs, constrain model behavior, segregate external content as data not instructions
- **LLM02: Sensitive Information Disclosure** — Sanitize training data, filter outputs, enforce access controls in RAG
- **LLM03: Supply Chain** — Verify model provenance, maintain SBOMs, use trusted model sources only
- **LLM04: Data and Model Poisoning** — Validate training data, detect anomalies, use sandboxed fine-tuning pipelines
- **LLM05: Improper Output Handling** — Treat LLM output as untrusted; sanitize before downstream use

### High Impact

- **LLM06: Excessive Agency** — Apply least privilege; require human approval for high-impact actions
- **LLM07: System Prompt Leakage** — Never put secrets in system prompts; use external guardrails
- **LLM08: Vector and Embedding Weaknesses** — Access-control RAG retrievals; validate data sources
- **LLM10: Unbounded Consumption** — Rate limiting, input size limits, cost monitoring

## Quick Reference

| Vulnerability | Key Prevention |
|--------------|----------------|
| Prompt Injection | Input validation, output filtering, privilege separation |
| Sensitive Disclosure | Data sanitization, access controls, encryption |
| Supply Chain | Verify models, SBOM, trusted sources only |
| Data Poisoning | Data validation, anomaly detection, sandboxing |
| Output Handling | Treat LLM as untrusted, encode outputs, parameterize queries |
| Excessive Agency | Least privilege, human-in-the-loop, minimize extensions |
| System Prompt Leakage | No secrets in prompts, external guardrails |
| Vector/Embedding | Access controls, data validation, monitoring |
| Misinformation | RAG, fine-tuning, human oversight, cross-verification |
| Unbounded Consumption | Rate limiting, input validation, resource monitoring |

## Agent Instructions

When reviewing or building LLM applications, automatically apply these checks:

1. **User input passed to LLM** → Read `rules/prompt-injection.md`
2. **PII or credentials in model context** → Read `rules/sensitive-disclosure.md`
3. **Third-party models or fine-tuning pipelines** → Read `rules/supply-chain.md`
4. **Training data ingestion** → Read `rules/data-poisoning.md`
5. **LLM output used in code, SQL, or HTML** → Read `rules/output-handling.md`
6. **LLM tools or function calling** → Read `rules/excessive-agency.md`
7. **System prompt design** → Read `rules/system-prompt-leakage.md`
8. **RAG or embedding pipelines** → Read `rules/vector-embedding.md`
9. **LLM model results** → Read `rules/misinformation.md`
10. **API endpoints exposed by LLM apps** → Read `rules/unbounded-consumption.md`

If a vulnerability is detected, report it with:
- **OWASP LLM category** (LLM01–LLM10)
- **Severity level** (CRITICAL / HIGH / MEDIUM)
- **Specific pattern** that is vulnerable
- **Recommended fix** with a code example from the relevant rule file

## Key Principles

1. **Never trust LLM output** — validate and sanitize all outputs before use
2. **Least privilege** — grant minimum necessary permissions to LLM systems
3. **Defense in depth** — layer multiple security controls
4. **Human oversight** — require approval for high-impact actions
5. **Monitor and log** — track all LLM interactions for anomaly detection

## References

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Prismor](https://github.com/PrismorSec/prismor)
