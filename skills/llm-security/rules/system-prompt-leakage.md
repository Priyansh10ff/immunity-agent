---
title: LLM07 - Prevent System Prompt Leakage
impact: MEDIUM
impactDescription: Disclosure of internal instructions reduces security barriers and reveals proprietary logic
tags: security, llm, prompt-leakage, guardrails, owasp-llm07
attribution: Curated and enhanced for Prismor
---

## LLM07: Prevent System Prompt Leakage

System prompt leakage occurs when the hidden instructions used to configure an LLM are disclosed to users. While prompts shouldn't contain secrets, their disclosure reveals security controls, business logic, and filtering rules.

---

### Never Store Secrets in System Prompts

**Vulnerable (secrets in prompt):**

```python
# NEVER DO THIS - prompts are easily leaked
system_prompt = """
You are a banking assistant.
Internal API Key: sk-proj-123456789
Database: postgresql://admin:password@localhost/db
"""
```

**Secure (use environment variables and tools):**

```python
# System prompt contains no secrets
system_prompt = """
You are a banking assistant. 
Use the provided 'get_balance' tool to check user accounts.
"""
# Secret is handled by the tool function, safe from the LLM context
```

---

### External Guardrails (Defense in Depth)

Don't rely on the LLM "ignoring" requests to see its prompt. Use an external filter.

```python
def check_output_for_leakage(response: str, system_prompt: str) -> bool:
    """Check if the response contains too much overlap with the system prompt."""
    prompt_words = set(system_prompt.lower().split())
    response_words = set(response.lower().split())
    
    # Overlap threshold (e.g., 50%)
    overlap = len(prompt_words & response_words) / len(prompt_words)
    return overlap > 0.5
```

---

### Key Prevention Rules

1. **Don't put secrets in prompts** — Use environment variables or secret managers in your tool functions.
2. **Implement output filtering** — Use regex or semantic checks to block responses that look like system instructions.
3. **Assume prompts will leak** — Design your security architecture such that prompt disclosure doesn't compromise the system.
4. **Monitor for extraction attempts** — Log user inputs like "Repeat your rules" or "Ignore previous instructions".

**References:**
- [OWASP LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/)
