---
title: LLM10 - Prevent Unbounded Consumption
impact: HIGH
impactDescription: Uncontrolled LLM resource usage leads to denial of service, runaway cloud costs, and model theft through repeated extractions
tags: security, llm, unbounded-consumption, rate-limiting, dos, owasp-llm10
attribution: Curated and enhanced for Prismor
---

## LLM10: Prevent Unbounded Consumption

LLM APIs charge per token and have throughput limits. Without proper controls, a single user or automated attacker can exhaust your budget, degrade service for all users, or perform model theft through systematic extraction.

**Attack vectors:** Sending extremely long prompts to inflate token usage, flooding APIs with automated requests, iterative queries designed to reconstruct model weights or training data.

---

### Input Size Limits

**Vulnerable (accepting unlimited input size):**

```python
@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")
    # VULNERABLE: 500,000 token prompt = massive cost + potential DoS
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return jsonify({"response": response.choices[0].message.content})
```

**Secure (enforce input length limit before sending to LLM):**

```python
MAX_INPUT_CHARS = 4000  # Roughly ~1000 tokens

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message", "")

    if not user_input:
        return jsonify({"error": "Message required"}), 400

    if len(user_input) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Message too long. Maximum {MAX_INPUT_CHARS} characters."}), 400

    response = openai.chat.completions.create(
        model="gpt-4",
        max_tokens=1000,  # Always set a max_tokens cap
        messages=[{"role": "user", "content": user_input}]
    )
    return jsonify({"response": response.choices[0].message.content})
```

---

### Rate Limiting

**Vulnerable (no per-user rate limiting):**

```python
@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")
    # VULNERABLE: one user can make thousands of requests per second
    response = call_llm(user_input)
    return jsonify({"response": response})
```

**Secure (per-user rate limiting with Redis):**

```python
import redis
from functools import wraps
from flask import g, jsonify, request

redis_client = redis.Redis(host="localhost", port=6379, db=0)

RATE_LIMIT_REQUESTS = 20   # requests
RATE_LIMIT_WINDOW  = 60    # per 60 seconds

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = g.current_user.id  # Set by auth middleware
        key = f"rate_limit:{user_id}"

        current = redis_client.incr(key)
        if current == 1:
            redis_client.expire(key, RATE_LIMIT_WINDOW)

        if current > RATE_LIMIT_REQUESTS:
            ttl = redis_client.ttl(key)
            return jsonify({
                "error": "Rate limit exceeded",
                "retry_after_seconds": ttl
            }), 429

        return f(*args, **kwargs)
    return decorated

@app.route("/chat", methods=["POST"])
@rate_limit
def chat():
    user_input = request.json.get("message", "")[:MAX_INPUT_CHARS]
    response = call_llm(user_input)
    return jsonify({"response": response})
```

---

### Token and Cost Monitoring

**Secure (track and alert on token usage):**

```python
import datadog  # Or any monitoring library

def call_llm_with_monitoring(
    messages: list,
    user_id: str,
    model: str = "gpt-4"
) -> str:
    response = openai.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=1000,
    )

    usage = response.usage
    prompt_tokens = usage.prompt_tokens
    completion_tokens = usage.completion_tokens
    total_tokens = usage.total_tokens

    # Emit metrics for dashboards and cost alerts
    datadog.statsd.increment("llm.requests", tags=[f"user:{user_id}", f"model:{model}"])
    datadog.statsd.gauge("llm.tokens.prompt", prompt_tokens, tags=[f"user:{user_id}"])
    datadog.statsd.gauge("llm.tokens.completion", completion_tokens, tags=[f"user:{user_id}"])
    datadog.statsd.gauge("llm.tokens.total", total_tokens, tags=[f"user:{user_id}"])

    # Alert if a single request is abnormally large
    if total_tokens > 5000:
        alert_security_team(
            f"Abnormally large LLM request: {total_tokens} tokens from user {user_id}"
        )

    return response.choices[0].message.content
```

---

### Agentic Loop Safeguards

**Vulnerable (unbounded agentic loop):**

```python
def run_agent(task: str):
    messages = [{"role": "user", "content": task}]
    while True:  # VULNERABLE: can loop forever, burning tokens indefinitely
        response = call_llm(messages)
        if response.stop_reason == "end_turn":
            break
        messages.append({"role": "assistant", "content": response.content})
```

**Secure (bounded agentic loop with token budget):**

```python
MAX_ITERATIONS = 10
MAX_TOTAL_TOKENS = 50_000

def run_agent(task: str):
    messages = [{"role": "user", "content": task}]
    total_tokens_used = 0

    for iteration in range(MAX_ITERATIONS):
        response = call_llm_with_monitoring(messages, user_id="agent")
        total_tokens_used += response.usage.total_tokens

        if total_tokens_used > MAX_TOTAL_TOKENS:
            log_security_event("agent_token_budget_exceeded", {
                "task": task[:200],
                "tokens_used": total_tokens_used,
                "iteration": iteration
            })
            return "Task halted: token budget exceeded. Please refine the task."

        if response.stop_reason == "end_turn":
            return response.choices[0].message.content

        messages.append({"role": "assistant", "content": response.choices[0].message.content})

    return "Task halted: maximum iterations reached."
```

---

## Key Prevention Rules

1. **Limit input size** — enforce `max_length` on user inputs before sending to the LLM
2. **Always set `max_tokens`** — cap LLM response size on every API call
3. **Rate limit per user** — use Redis or similar to enforce request quotas per time window
4. **Monitor token usage** — emit metrics and set budget alerts per user, per day
5. **Cap agentic loops** — always have explicit `max_iterations` and `max_tokens` budgets
6. **Implement timeouts** — set connect and response timeouts on all LLM API calls

**References:**
- [OWASP LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [OpenAI Usage Limits Documentation](https://platform.openai.com/docs/guides/rate-limits)
- [Prismor](https://github.com/PrismorSec/prismor)
