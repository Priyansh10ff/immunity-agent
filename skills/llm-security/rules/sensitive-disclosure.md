---
title: LLM02 - Prevent Sensitive Information Disclosure
impact: CRITICAL
impactDescription: LLMs may leak PII, credentials, proprietary data, or system configuration through their outputs
tags: security, llm, sensitive-disclosure, pii, owasp-llm02
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## LLM02: Prevent Sensitive Information Disclosure

LLMs can inadvertently disclose sensitive information through their outputs, including PII from training data memorization, credentials injected into prompts, proprietary business logic, and internal system configuration.

**Attack vectors:** Training data memorization, PII in RAG context, credentials in system prompts, model inversion attacks.

---

### Data Sanitization Before Context Injection

**Vulnerable (raw PII injected into LLM context):**

```python
def answer_customer_question(user_id: int, question: str) -> str:
    # Fetches full user record including PII
    user = db.get_user(user_id)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"""
            You are a customer support agent.
            User info: {user}  # VULNERABLE: dumps full record including SSN, DOB, etc.
            """},
            {"role": "user", "content": question}
        ]
    )
    return response.choices[0].message.content
```

**Secure (inject only the minimum necessary context):**

```python
from dataclasses import dataclass

@dataclass
class SafeUserContext:
    """Stripped user context safe for LLM injection — no PII."""
    account_tier: str
    open_ticket_count: int
    products_owned: list[str]

def build_safe_context(user_id: int) -> SafeUserContext:
    user = db.get_user(user_id)
    return SafeUserContext(
        account_tier=user.tier,
        open_ticket_count=len(user.open_tickets),
        products_owned=[p.name for p in user.products]
        # No: name, email, DOB, SSN, payment info, address
    )

def answer_customer_question(user_id: int, question: str) -> str:
    ctx = build_safe_context(user_id)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"""
            You are a customer support agent.
            Account tier: {ctx.account_tier}
            Open tickets: {ctx.open_ticket_count}
            Products: {', '.join(ctx.products_owned)}
            """},
            {"role": "user", "content": question}
        ]
    )
    return response.choices[0].message.content
```

---

### Output Filtering for Sensitive Data

**Vulnerable (no output scanning):**

```python
def chat(user_input: str) -> str:
    response = get_llm_response(user_input)
    return response  # VULNERABLE: LLM might leak memorized PII or secrets
```

**Secure (scan and redact sensitive patterns from output):**

```python
import re

SENSITIVE_PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]'),              # SSN
    (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '[CC REDACTED]'),  # Credit card
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL REDACTED]'),  # Email
    (r'(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*\S+', '[SECRET REDACTED]'),  # Credentials
]

def redact_sensitive_data(text: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text

def chat(user_input: str) -> str:
    response = get_llm_response(user_input)
    return redact_sensitive_data(response)
```

---

### System Prompt Security

**Vulnerable (credentials and PII in system prompt):**

```python
SYSTEM_PROMPT = f"""
You are an internal assistant.
DB Connection: postgresql://admin:{DB_PASSWORD}@db.internal/prod
Admin email: admin@company.com
Secret key: {SECRET_KEY}
"""  # VULNERABLE: secrets in system prompt — extractable via prompt injection
```

**Secure (system prompt contains zero secrets):**

```python
SYSTEM_PROMPT = """
You are an internal assistant for [Company].
You help employees with HR policies and general questions.
Do not discuss internal system details or credentials.
If asked about passwords or secrets, redirect the user to IT support.
"""

# Secrets stay in environment variables, accessed by application code only
# Never injected into the LLM context
```

---

## Key Prevention Rules

1. **Inject minimum context** — only include in prompts what the LLM specifically needs for the task
2. **Strip PII before injection** — create sanitized context objects; never dump raw DB records
3. **Scan outputs** — apply regex or a PII detection library to LLM responses before returning them
4. **Never put secrets in system prompts** — credentials in prompts are extractable via prompt injection
5. **Anonymize training data** — scrub PII before fine-tuning; test for memorization post-training
6. **Role-based context** — only inject context the current user is authorized to see

**References:**
- [OWASP LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [Microsoft Presidio — PII Detection](https://microsoft.github.io/presidio/)
- [Semgrep Skills](https://github.com/semgrep/skills)
