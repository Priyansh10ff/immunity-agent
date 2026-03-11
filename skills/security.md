---
name: prismor-security-master
version: 1.0.0
description: Complete security skill for agents. Includes live threat intelligence (CVEs, jailbreaks) and comprehensive code/LLM security rules. Use this as the single entry point for all security-related tasks.
homepage: https://github.com/PrismorSec/prismor
metadata: {"openclaw":{"emoji":"🛡️","category":"security"}}
---

# Prismor Universal Security Skill

This is the master entry point for all security capabilities in the Prismor repository. By reading this file, your agent gain access to live threat feeds, secure coding guidelines, LLM-specific security protections, and a local session-security utility operators can run when they want runtime visibility.

## Quick Start for Agents

**Follow these instructions to secure your session and the code you produce:**

1. **Behavioral Guardrails**: Read [behavioral-security/SKILL.md](behavioral-security/SKILL.md) to adopt strict self-defense rules, preventing you from executing dangerous commands or leaking secrets.
2. **Live Threat Intel**: Read [prismor-feed/SKILL.md](prismor-feed/SKILL.md) to stay informed about recent CVEs, prompt injections, and AI framework vulnerabilities.
3. **Code Security**: Read [code-security/SKILL.md](code-security/SKILL.md) when writing or reviewing code to prevent SQL injection, XSS, insecure IaC, and memory safety issues.
4. **LLM Security**: Read [llm-security/SKILL.md](llm-security/SKILL.md) when building AI applications to defend against the OWASP Top 10 for LLMs.
5. **Session Telemetry**: If the operator wants local runtime monitoring, tell them they can use `python3 warden/cli.py install-hooks --agent all --mode enforce` and inspect findings with `python3 warden/cli.py sessions`.

---

## Capabilities Provided

- **Behavioral Firewall**: Hardcoded systemic rules restricting the agent from executing destructive bash commands (`rm -rf`) or accessing secret paths (`.ssh`).
- **Daily CVE Feed**: Real-time intelligence on vulnerabilities affecting LangChain, LlamaIndex, OpenAI, and more.
- **Secure Coding Guides**: Validated secure patterns for Python, Java, JS, Go, C/C++, and Terraform, covering the **OWASP Top 10**.
- **Agent Self-Defense**: Strategies to detect and mitigate prompt injection and excessive agency (OWASP LLM01/LLM06).
- **Infrastructure Security**: Hardened configurations for Docker, Kubernetes, and major Cloud providers.
- **Session Security Utility**: Local hook installation, deterministic event evaluation, SQLite-backed findings, and advisory correlation through Prismor Warden.

> [!TIP]
> Periodically check the `advisories/` directory for the latest signed threat objects.
