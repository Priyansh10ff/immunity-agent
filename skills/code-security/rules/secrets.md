---
title: Prevent Hardcoded Secrets
impact: CRITICAL
impactDescription: Credentials exposed in source code can be harvested from version control history, giving attackers full access to services
tags: security, secrets, credentials, cwe-798, owasp-a02
attribution: Curated and enhanced for Prismor
---

## Prevent Hardcoded Secrets

Hardcoded secrets (passwords, API keys, tokens, connection strings) are frequently discovered in version control history, public repositories, and build artifacts. Once leaked, secrets are compromised even after they are removed from the codebase — rotation is the only remedy.

**Vulnerable patterns:** String literals assigned to variables named `password`, `api_key`, `secret`, `token`, `private_key`; connection strings with embedded credentials.

---

### Python

**Incorrect (hardcoded credentials):**

```python
import openai
import psycopg2

# VULNERABLE: secrets hardcoded in source
openai.api_key = "sk-abc123realkey..."
DB_PASSWORD = "supersecretpassword"

conn = psycopg2.connect(
    host="db.example.com",
    user="admin",
    password="supersecretpassword"  # VULNERABLE
)
```

**Correct (use environment variables):**

```python
import os
import openai
import psycopg2

openai.api_key = os.environ["OPENAI_API_KEY"]

conn = psycopg2.connect(
    host=os.environ["DB_HOST"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"]
)
```

---

### JavaScript / Node.js

**Incorrect (hardcoded secrets):**

```javascript
const stripe = require('stripe');

// VULNERABLE: hardcoded in source
const client = stripe('sk_live_abc123realkey...');
const DB_URL = 'postgresql://admin:password123@db.example.com/mydb';
```

**Correct (use environment variables):**

```javascript
const stripe = require('stripe');

const client = stripe(process.env.STRIPE_SECRET_KEY);
const DB_URL = process.env.DATABASE_URL;
```

---

### Java

**Incorrect (hardcoded credentials in Spring configuration):**

```java
@Configuration
public class DataSourceConfig {
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl("jdbc:postgresql://db.example.com/mydb");
        ds.setUsername("admin");
        ds.setPassword("supersecretpassword");  // VULNERABLE
        return ds;
    }
}
```

**Correct (use application.properties or environment variables):**

```java
@Configuration
public class DataSourceConfig {
    @Value("${DB_URL}")
    private String dbUrl;

    @Value("${DB_USERNAME}")
    private String dbUsername;

    @Value("${DB_PASSWORD}")
    private String dbPassword;

    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl(dbUrl);
        ds.setUsername(dbUsername);
        ds.setPassword(dbPassword);
        return ds;
    }
}
```

And in `application.properties`:
```properties
DB_URL=${DB_URL}
DB_USERNAME=${DB_USERNAME}
DB_PASSWORD=${DB_PASSWORD}
```

---

### Go

**Incorrect (hardcoded API key):**

```go
func getClient() *openai.Client {
    // VULNERABLE: hardcoded in source
    return openai.NewClient("sk-abc123realkey...")
}
```

**Correct (read from environment):**

```go
import "os"

func getClient() *openai.Client {
    apiKey := os.Getenv("OPENAI_API_KEY")
    if apiKey == "" {
        log.Fatal("OPENAI_API_KEY environment variable not set")
    }
    return openai.NewClient(apiKey)
}
```

---

### .env File Best Practices

Store secrets in a `.env` file **that is always in `.gitignore`**:

```bash
# .env (NEVER commit this file)
OPENAI_API_KEY=sk-abc123...
DATABASE_URL=postgresql://user:pass@host/db
JWT_SECRET=your-secret-here
```

```
# .gitignore
.env
.env.local
.env.*.local
```

Use a `.env.example` file with placeholder values that IS committed:

```bash
# .env.example (safe to commit — no real values)
OPENAI_API_KEY=your-openai-api-key-here
DATABASE_URL=postgresql://user:password@host/dbname
JWT_SECRET=your-jwt-secret-here
```

---

## Key Prevention Rules

1. **Use environment variables** — read secrets from `os.environ` / `process.env` / `os.Getenv`
2. **Use a secrets manager** — AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager for production
3. **Never commit `.env` files** — always add them to `.gitignore`
4. **Provide `.env.example`** — commit a template with placeholder values so teammates know what to set
5. **Rotate any secret that was ever committed** — removing it from history is not enough
6. **Use pre-commit hooks** — tools like `detect-secrets` or `gitleaks` catch secrets before they are pushed

**References:**
- [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [GitHub Docs: Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [Prismor](https://github.com/PrismorSec/prismor)
