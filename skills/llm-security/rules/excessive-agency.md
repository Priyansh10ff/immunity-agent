---
title: LLM06 - Control Excessive Agency
impact: HIGH
impactDescription: LLM agents with too many permissions or insufficient human oversight can take irreversible high-impact actions when manipulated by adversarial inputs
tags: security, llm, excessive-agency, owasp-llm06, agents
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## LLM06: Control Excessive Agency

Excessive agency occurs when an LLM is granted more permissions, functionality, or autonomy than necessary for the task. This risk is amplified when combined with prompt injection — an attacker who can control the LLM's instructions can also trigger any actions it has access to.

**Attack vectors:** Prompt injection leading to unintended tool calls, unbounded file system or network access, LLM agents with write/delete/send permissions making decisions without human approval.

---

### Minimizing Tool / Extension Functionality

**Vulnerable (broad tool access — read, write, send, delete):**

```python
tools = [
    {
        "name": "file_manager",
        "description": "Read, write, delete, or list any file on the system",
        "parameters": {
            "action": {"type": "string", "enum": ["read", "write", "delete", "list"]},
            "path": {"type": "string"},
            "content": {"type": "string"}
        }
    },
    {
        "name": "email_sender",
        "description": "Send email to any recipient",
        "parameters": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"}
        }
    },
    {
        "name": "database",
        "description": "Execute any SQL query",
        "parameters": {"query": {"type": "string"}}
    }
]
```

**Secure (scoped, read-only tools with no destructive capabilities):**

```python
tools = [
    {
        "name": "read_allowed_file",
        "description": "Read a file from the allowed documents directory only",
        "parameters": {
            "filename": {
                "type": "string",
                "description": "Filename only (no path). Must be in allowed_docs/."
            }
        }
    },
    {
        "name": "search_knowledge_base",
        "description": "Search the internal knowledge base. Read-only.",
        "parameters": {
            "query": {"type": "string", "maxLength": 500}
        }
    }
    # Note: NO email, NO delete, NO arbitrary SQL, NO write operations
]
```

---

### Implementing Least Privilege

**Vulnerable (single API key with full permissions):**

```python
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def run_agent(user_request: str):
    # This agent has access to all configured tools with no restrictions
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=4096,
        tools=ALL_TOOLS,  # VULNERABLE: full tool suite, including destructive ops
        messages=[{"role": "user", "content": user_request}]
    )
    # Execute whatever tool the LLM requested
    execute_tool(response.content)
```

**Secure (scoped permissions per task context):**

```python
def get_tools_for_context(task_type: str) -> list:
    """Return only the tools needed for the specific task type."""
    tool_map = {
        "read_only": [SEARCH_TOOL, READ_DOCUMENT_TOOL],
        "analysis": [SEARCH_TOOL, READ_DOCUMENT_TOOL, CALCULATE_TOOL],
        # write/delete tools require explicit operator opt-in AND human approval
    }
    return tool_map.get(task_type, [SEARCH_TOOL])

def run_agent(user_request: str, task_type: str = "read_only"):
    tools = get_tools_for_context(task_type)
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=2048,
        tools=tools,  # Scoped to task
        messages=[{"role": "user", "content": user_request}]
    )
    return response
```

---

### Human-in-the-Loop for High-Impact Actions

**Vulnerable (auto-execute all tool calls):**

```python
def run_agentic_loop(user_request: str):
    messages = [{"role": "user", "content": user_request}]

    while True:
        response = client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=4096,
            tools=tools,
            messages=messages
        )

        if response.stop_reason == "tool_use":
            for block in response.content:
                if block.type == "tool_use":
                    # VULNERABLE: auto-executes any tool without asking the user
                    result = execute_tool(block.name, block.input)
```

**Secure (human approval gate for high-impact actions):**

```python
HIGH_IMPACT_TOOLS = {"send_email", "delete_file", "execute_sql", "deploy_code"}

def requires_human_approval(tool_name: str, tool_input: dict) -> bool:
    if tool_name in HIGH_IMPACT_TOOLS:
        return True
    # Also require approval for large writes
    if tool_name == "write_file" and len(tool_input.get("content", "")) > 1000:
        return True
    return False

def run_agentic_loop(user_request: str):
    messages = [{"role": "user", "content": user_request}]

    while True:
        response = client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=4096,
            tools=tools,
            messages=messages
        )

        if response.stop_reason == "tool_use":
            for block in response.content:
                if block.type == "tool_use":
                    if requires_human_approval(block.name, block.input):
                        # Pause and ask the human operator
                        approved = get_human_approval(
                            tool_name=block.name,
                            tool_input=block.input,
                            context=user_request
                        )
                        if not approved:
                            # Inject refusal back into the conversation
                            messages.append({
                                "role": "user",
                                "content": f"Tool call '{block.name}' was denied by the operator. Please find an alternative approach."
                            })
                            continue

                    result = execute_tool(block.name, block.input)
                    log_tool_execution(block.name, block.input, result)
```

---

## Key Prevention Rules

1. **Minimize tool surface** — only expose tools the agent strictly needs; no "just in case" capabilities
2. **Scope permissions per task** — different task types get different tool subsets
3. **Require human approval** for all irreversible or high-impact actions (send, delete, deploy, write)
4. **Log every tool call** — maintain an audit trail of all agent actions for investigation
5. **Set resource limits** — cap the number of tool calls per session and the scope of each call
6. **Treat tool call parameters as untrusted** — validate inputs before executing; the LLM may have been injected

**References:**
- [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [Anthropic Agentic Safety Best Practices](https://docs.anthropic.com/claude/docs/agentic-and-multistep-tasks)
- [Semgrep Skills](https://github.com/semgrep/skills)
