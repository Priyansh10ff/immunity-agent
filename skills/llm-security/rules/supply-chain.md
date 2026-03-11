---
title: LLM03 - Secure LLM Supply Chain
impact: HIGH
impactDescription: Vulnerabilities in the LLM supply chain (models, data, dependencies) lead to backdoors, data poisoning, and arbitrary code execution
tags: security, llm, supply-chain, models, safetensors, owasp-llm03
attribution: Curated and enhanced for Prismor
---

## LLM03: Secure LLM Supply Chain

LLM supply chains include pre-trained models, fine-tuning data, embeddings, plugins, and deployment infrastructure. Vulnerabilities can arise from compromised model repositories, malicious training data, vulnerable dependencies, or tampered model files.

**Risk factors:** Unverified model sources, malicious pickle files, compromised LoRA adapters, outdated dependencies, unclear licensing.

---

### Model Verification

**Vulnerable (unverified model download):**

```python
from transformers import AutoModel

# Downloading without verification - could be a malicious model
model = AutoModel.from_pretrained("random-user/suspicious-model")
```

**Secure (verified model with integrity checks):**

```python
from transformers import AutoModel
import hashlib

TRUSTED_MODELS = {
    "meta-llama/Llama-2-7b-hf": {
        "sha256": "abc123...",  # Known good hash
        "verified_date": "2024-01-15"
    }
}

def load_verified_model(model_name: str):
    """Load model only from trusted sources with verification."""
    if model_name not in TRUSTED_MODELS:
        raise ValueError(f"Model {model_name} not trusted")

    # Use safe serialization (avoid pickle)
    model = AutoModel.from_pretrained(
        model_name,
        trust_remote_code=False,  # Never trust remote code
        use_safetensors=True,     # Use safe tensor format
    )
    return model
```

---

### Safe Model Loading (Avoid Pickle Exploits)

Pickle files can execute arbitrary code upon loading. Always prefer `safetensors`.

**Vulnerable (unsafe pickle loading):**

```python
import torch

# DANGEROUS: torch.load uses pickle internally by default
model = torch.load("model.pt") 
```

**Secure (safe tensor loading or restricted unpickler):**

```python
from safetensors.torch import load_file
import torch

def load_model_safely(model_path: str):
    if model_path.endswith(".safetensors"):
        return load_file(model_path)
    
    # For PyTorch models, use weights_only=True (Python 3.10+)
    return torch.load(model_path, weights_only=True)
```

---

### Key Prevention Rules

1. **Verify model sources** — Only use models from trusted organizations (e.g., official Hugging Face orgs).
2. **Use safe serialization** — Prefer `safetensors` over `.pt`, `.pkl`, or `.pickle` formats.
3. **Pin dependencies** — Use exact versions with hash verification in `requirements.txt`.
4. **Never trust remote code** — Set `trust_remote_code=False` in Transformers.
5. **Audit your ML-BOM** — Track all model components, datasets, and adapters used.

**References:**
- [OWASP LLM03:2025 Supply Chain](https://genai.owasp.org/llmrisk/llm03-supply-chain/)
- [Safetensors Documentation](https://huggingface.co/docs/safetensors/)
