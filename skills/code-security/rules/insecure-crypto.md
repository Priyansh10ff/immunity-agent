---
title: Prevent Insecure Cryptography
impact: HIGH
impactDescription: Weak algorithms allow attackers to decrypt data, forge signatures, and crack password hashes
tags: security, crypto, cwe-327, cwe-328, owasp-a02
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## Prevent Insecure Cryptography

Using outdated or broken cryptographic algorithms (MD5, SHA-1, DES, RC4, ECB mode) provides minimal or no security. Always use modern, well-reviewed algorithms with appropriate key sizes and modes.

**Vulnerable patterns:** MD5 or SHA1 for password hashing or data integrity, DES/3DES encryption, AES in ECB mode, using random as a CSPRNG for security purposes, storing passwords as plain hashes without salt.

---

### Hashing: Use SHA-256+ (not MD5 / SHA-1)

**Incorrect (MD5 for integrity check):**

```python
import hashlib

def get_file_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # VULNERABLE: MD5 is broken
```

**Incorrect (SHA-1):**

```python
def get_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # VULNERABLE: SHA-1 is deprecated
```

**Correct (SHA-256):**

```python
def get_file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()  # Safe: SHA-256 or SHA-3
```

---

### Password Hashing: Use bcrypt / Argon2 / scrypt (not raw SHA)

**Incorrect (hashing passwords with SHA-256 without salt):**

```python
import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()  # VULNERABLE: fast hash, no salt
```

**Correct (use bcrypt):**

```python
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)
```

**Correct (use Argon2 — recommended for new systems):**

```python
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return ph.verify(hashed, password)
```

---

### Symmetric Encryption: Use AES-256-GCM (not DES / ECB)

**Incorrect (DES encryption):**

```python
from Crypto.Cipher import DES

def encrypt(data: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)  # VULNERABLE: DES is broken, ECB leaks patterns
    return cipher.encrypt(data)
```

**Incorrect (AES in ECB mode):**

```python
from Crypto.Cipher import AES

def encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)  # VULNERABLE: ECB reveals data patterns
    return cipher.encrypt(data)
```

**Correct (AES-256-GCM with random nonce):**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)  # 96-bit nonce — never reuse per key
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext

def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
```

---

### JavaScript / Node.js

**Incorrect (MD5 hash):**

```javascript
const crypto = require('crypto');

function hashData(data) {
    return crypto.createHash('md5').update(data).digest('hex');  // VULNERABLE
}
```

**Correct (SHA-256 hash / bcrypt for passwords):**

```javascript
const crypto = require('crypto');
const bcrypt = require('bcrypt');

function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');  // Safe
}

async function hashPassword(password) {
    return bcrypt.hash(password, 12);  // Safe: bcrypt with cost factor 12
}
```

---

### Java

**Incorrect (MD5 or weak key size):**

```java
MessageDigest md = MessageDigest.getInstance("MD5");  // VULNERABLE
byte[] hash = md.digest(data);

// VULNERABLE: DES
KeyGenerator kg = KeyGenerator.getInstance("DES");
```

**Correct (SHA-256, AES-256):**

```java
MessageDigest md = MessageDigest.getInstance("SHA-256");  // Safe
byte[] hash = md.digest(data);

// Safe: AES-256
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);
```

---

## Key Prevention Rules

1. **Hashing** — use SHA-256 or SHA-3; never MD5 or SHA-1 for security-sensitive uses
2. **Password storage** — use Argon2id, bcrypt (cost ≥12), or scrypt; never raw SHA hashes
3. **Symmetric encryption** — use AES-256-GCM; avoid DES, 3DES, RC4, and AES-ECB
4. **Key management** — generate keys using a CSPRNG (`os.urandom`, `crypto.randomBytes`)
5. **Never reuse nonces/IVs** — especially in GCM mode; nonce reuse is catastrophic

**Algorithm Quick Reference:**

| Purpose | Use | Avoid |
|---------|-----|-------|
| General hashing | SHA-256, SHA-3 | MD5, SHA-1 |
| Password hashing | Argon2id, bcrypt | SHA-256 (unsalted) |
| Symmetric encryption | AES-256-GCM | DES, 3DES, AES-ECB |
| Asymmetric encryption | RSA-2048+, Ed25519 | RSA-512, DSA |

**References:**
- [CWE-327: Broken Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Semgrep Skills](https://github.com/semgrep/skills)
