---
title: LLM09 - Mitigate Hallucinations
impact: MEDIUM
impactDescription: LLMs generating false but plausible-sounding information leads to user harm, legal liability, and brand damage
tags: security, llm, hallucinations, rag, fact-checking, owasp-llm09
attribution: Curated and enhanced for Prismor
---

## LLM09: Mitigate Misinformation and Hallucinations

Hallucinations occur when LLMs generate fabricated facts. While not always a direct security breach, they can be weaponized or lead to unsafe actions in critical domains like medical or legal advice.

---

### Grounded Generation (RAG)

**Vulnerable (unbound generation):**

```python
def answer():
    # Pure LLM generation - prone to making things up
    return llm.generate("What is our company's refund policy?")
```

**Secure (RAG with citations):**

```python
def answer_with_grounding(query: str):
    docs = vector_store.search(query)
    context = "\n".join([d.content for d in docs])
    
    prompt = f"Answer based ONLY on the following context:\n{context}\n\nQuestion: {query}"
    response = llm.generate(prompt)
    return response, [d.source for d in docs]
```

---

### Key Prevention Rules

1. **Use RAG for facts** — Ground all factual answers in a verified knowledge base.
2. **Implement citations** — Require the model to cite specific sources for every claim.
3. **Low-temperature settings** — Use lower temperature (e.g., 0.1 to 0.3) for factual tasks to reduce creativity.
4. **Domain-specific guardrails** — Add hardcoded disclaimers for high-stakes domains (legal, medical, financial).
5. **Human review** — For critical outputs, implement a human-in-the-loop review process.

**References:**
- [OWASP LLM09:2025 Misinformation](https://genai.owasp.org/llmrisk/llm09-misinformation/)
- [RAG for Grounded Generation](https://arxiv.org/abs/2005.11401)
