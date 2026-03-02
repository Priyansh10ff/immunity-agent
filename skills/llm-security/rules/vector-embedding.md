---
title: LLM08 - Secure Vector and Embedding Systems
impact: HIGH
impactDescription: Unauthorized access to sensitive data in vector databases or extraction of data from shared embeddings
tags: security, llm, vector-db, rag, multitenancy, owasp-llm08
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## LLM08: Secure Vector and Embedding Systems

Vector databases used in RAG systems can leak sensitive information if not properly isolated. Risks include unauthorized retrieval of documents and cross-tenant data leaks.

---

### Permission-Aware Vector Retrieval

**Vulnerable (no access control):**

```python
def search_documents(query: str) -> list[str]:
    # Retrieves from the entire DB regardless of who is asking
    embedding = embed_model.encode(query)
    results = vector_db.similarity_search(embedding, k=5)
    return [r.content for r in results]
```

**Secure (tenant/user filtering):**

```python
def search_documents_secure(query: str, tenant_id: str) -> list[str]:
    embedding = embed_model.encode(query)
    
    # Apply strict metadata filter for isolation
    results = vector_db.similarity_search(
        embedding, 
        k=5, 
        filter={"tenant_id": tenant_id} 
    )
    return [r.content for r in results]
```

---

### Key Prevention Rules

1. **Enforce access controls** — Apply the same permission checks to your vector DB as you do to your primary database.
2. **Strict tenant isolation** — Use separate collections or mandatory metadata filters for multi-tenant systems.
3. **Validate before embedding** — Check documents for prompt injection or malicious content before adding them to the vector store.
4. **Don't expose raw embeddings** — Raw vectors can sometimes be "inverted" to reconstruct original text. Keep embedding APIs internal.

**References:**
- [OWASP LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/)
