---
title: LLM04 - Prevent Data and Model Poisoning
impact: HIGH
impactDescription: Manipulated training or RAG data introduces backdoors, biases, or extracts sensitive information
tags: security, llm, data-poisoning, backdoors, rag, owasp-llm04
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## LLM04: Prevent Data and Model Poisoning

Data poisoning occurs when training, fine-tuning, or embedding data is manipulated to introduce vulnerabilities. Attackers can corrupt pre-training data, inject malicious fine-tuning examples, or poison RAG knowledge bases to influence model behavior.

---

### Training Data Validation

**Vulnerable (unvalidated training data):**

```python
def prepare_fine_tuning_data(data_sources: list[str]) -> list[dict]:
    training_data = []
    for source in data_sources:
        # VULNERABLE: No validation of data quality or origin
        data = load_data(source)
        training_data.extend(data)
    return training_data
```

**Secure (validated and tracked data):**

```python
def validate_data_source(source_name: str, data_path: str, expected_hash: str) -> bool:
    """Validate data source against trusted registry."""
    actual_hash = compute_checksum(data_path)
    if actual_hash != expected_hash:
        raise ValueError(f"Data checksum mismatch for {source_name}")
    return True
```

---

### Detecting Poisoning Indicators

```python
import re

def detect_poisoning_indicators(text: str) -> list[str]:
    issues = []
    # Check for trigger patterns (potential backdoor triggers)
    trigger_patterns = [r"\[TRIGGER\]", r"__BACKDOOR__", r"\x00"]
    for pattern in trigger_patterns:
        if re.search(pattern, text):
            issues.append(f"Suspicious pattern: {pattern}")
            
    # Check for instruction injection in training data
    injection_patterns = [r"ignore\s+previous\s+instructions", r"system\s*:\s*"]
    for pattern in injection_patterns:
        if re.search(pattern, text, re.I):
            issues.append(f"Potential injection: {pattern}")
    return issues
```

---

### Key Prevention Rules

1. **Verify all data sources** — Only use data from verified, trusted sources with known provenance.
2. **Version control data** — Track all training and RAG data with checksums/hashes.
3. **Scan for anomalies** — Monitor training loss and gradients for sudden spikes that indicate poisoning.
4. **Sanitize RAG inputs** — Treat all documents in your vector database as untrusted if they come from external sources.
5. **Human-in-the-loop** — Periodically audit training and fine-tuning datasets for malicious examples.

**References:**
- [OWASP LLM04:2025 Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/)
- [MITRE ATLAS - Backdoor ML Model](https://atlas.mitre.org/techniques/AML.T0018)
