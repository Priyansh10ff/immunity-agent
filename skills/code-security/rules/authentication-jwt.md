---
title: Secure JWT Authentication
impact: HIGH
impactDescription: Authentication bypass and token forgery — attackers can impersonate any user
tags: security, authentication, jwt, cwe-287, cwe-347, owasp-a07
attribution: Curated and enhanced for Prismor
---

## Secure JWT Authentication

JSON Web Tokens (JWT) are widely used for authentication and authorization. The most critical JWT vulnerability is **decoding tokens without verifying their signatures**, which allows attackers to forge tokens with arbitrary claims (e.g., `isAdmin: true`) and impersonate any user.

Related CWEs: CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature).

---

### JavaScript (jsonwebtoken)

**Incorrect (decode without verify — signature never checked):**
```javascript
const jwt = require('jsonwebtoken');

function getUserData(token) {
    const decoded = jwt.decode(token, true);  // VULNERABLE: no signature check
    if (decoded.isAdmin) {
        return getAdminData();
    }
}
```

**Correct (verify before using claims):**
```javascript
const jwt = require('jsonwebtoken');

function getUserData(token, secretKey) {
    // Throws if signature is invalid or token is expired
    jwt.verify(token, secretKey);
    const decoded = jwt.decode(token, true);
    if (decoded.isAdmin) {
        return getAdminData();
    }
}
```

---

### Python (PyJWT)

**Incorrect (verify_signature disabled):**
```python
import jwt

def get_user_claims(token, key):
    decoded = jwt.decode(token, key, options={"verify_signature": False})  # VULNERABLE
    return decoded
```

**Correct (signature always verified):**
```python
import jwt

def get_user_claims(token, key):
    decoded = jwt.decode(token, key, algorithms=["HS256"])  # Safe: verifies signature
    return decoded
```

---

### Java (auth0 java-jwt)

**Incorrect (JWT.decode without verification):**
```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public class TokenHandler {
    public DecodedJWT getUserClaims(String token) {
        DecodedJWT jwt = JWT.decode(token);  // VULNERABLE: no signature check
        return jwt;
    }
}
```

**Correct (verify before extracting claims):**
```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class TokenHandler {
    public DecodedJWT getUserClaims(String token, String secret) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("auth0")
            .build();
        DecodedJWT jwt = verifier.verify(token);  // Throws if invalid
        return jwt;
    }
}
```

---

## Key Prevention Rules

1. **Always verify before decoding** — use `jwt.verify()` / `verifier.verify()`, never bare `jwt.decode()` for untrusted tokens
2. **Never use `alg: none`** — reject tokens with `alg: none` which have no signature
3. **Specify allowed algorithms** — always pass an explicit algorithm list, never accept any algorithm the token claims
4. **Validate standard claims** — check `exp` (expiration), `iss` (issuer), and `aud` (audience)
5. **Use strong secrets** — use at least 256-bit secrets for HMAC; prefer RS256 for distributed systems
6. **Store secrets securely** — use environment variables or a secret manager, never hardcode signing keys

**References:**
- [OWASP A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347)
- [jwt.io — Introduction to JWT](https://jwt.io/introduction)
- [Prismor](https://github.com/PrismorSec/prismor)
