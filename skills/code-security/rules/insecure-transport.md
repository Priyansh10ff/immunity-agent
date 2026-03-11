---
title: Prevent Insecure Transport
impact: HIGH
impactDescription: Data transmitted without TLS can be intercepted or modified by network attackers via man-in-the-middle attacks
tags: security, tls, https, cwe-319, owasp-a02
attribution: Curated and enhanced for Prismor
---

## Prevent Insecure Transport

Transmitting sensitive data over unencrypted HTTP or with improperly configured TLS exposes it to interception. Always use HTTPS with a verified, modern TLS configuration that disables weak protocol versions and cipher suites.

**Vulnerable patterns:** Plain `http://` URLs for sensitive data, `verify=False` in HTTP clients, `InsecureSkipVerify: true` in TLS configs, allowing TLS 1.0/1.1 or weak cipher suites.

---

### Python

**Incorrect (disabling TLS certificate verification):**

```python
import requests

# VULNERABLE: disables certificate validation entirely
response = requests.get("https://api.example.com/data", verify=False)
```

**Incorrect (plain HTTP for sensitive data):**

```python
response = requests.get("http://api.example.com/sensitive-data")  # VULNERABLE
```

**Correct (HTTPS with verification enabled — the default):**

```python
import requests

# Safe: verify=True is the default; include it explicitly for clarity
response = requests.get("https://api.example.com/data", verify=True, timeout=10)
```

**Correct (pinning a certificate bundle):**

```python
response = requests.get(
    "https://api.example.com/data",
    verify="/path/to/ca-bundle.crt",
    timeout=10
)
```

---

### JavaScript / Node.js

**Incorrect (disabling TLS validation):**

```javascript
const https = require('https');

// VULNERABLE: rejectUnauthorized disables certificate checking
const agent = new https.Agent({ rejectUnauthorized: false });
const response = await fetch('https://api.example.com/data', { agent });
```

**Incorrect (NODE_TLS_REJECT_UNAUTHORIZED env var set to 0):**

```javascript
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';  // VULNERABLE: disables TLS globally
```

**Correct (default TLS settings, HTTPS only):**

```javascript
// Safe: default https.Agent validates certificates
const response = await fetch('https://api.example.com/data');
```

---

### Go

**Incorrect (InsecureSkipVerify):**

```go
import "crypto/tls"

client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,  // VULNERABLE: skip cert validation
        },
    },
}
resp, err := client.Get("https://api.example.com/data")
```

**Correct (default TLS config which verifies certificates):**

```go
// Safe: default http.Client validates TLS certificates
resp, err := http.Get("https://api.example.com/data")
```

**Correct (enforce minimum TLS version for servers):**

```go
server := &http.Server{
    Addr: ":443",
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,  // Disable TLS 1.0 and 1.1
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    },
}
server.ListenAndServeTLS("cert.pem", "key.pem")
```

---

### Java

**Incorrect (trust all certificates):**

```java
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        // VULNERABLE: accepts any certificate
    }
};
SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
```

**Correct (use default JSSE trust store):**

```java
// Safe: Java's default HTTPS handling validates certificates
URL url = new URL("https://api.example.com/data");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setConnectTimeout(5000);
conn.setReadTimeout(5000);
```

---

## Key Prevention Rules

1. **Always use HTTPS** — never transmit sensitive data over plain HTTP
2. **Never disable certificate validation** — `verify=False`, `InsecureSkipVerify`, `rejectUnauthorized: false` are for testing only
3. **Enforce TLS 1.2+** — disable TLSv1.0 and TLSv1.1 on servers
4. **Use strong cipher suites** — prefer ECDHE + AES-GCM or ChaCha20-Poly1305
5. **Add HTTP Strict Transport Security (HSTS)** — prevents protocol downgrade attacks
6. **Redirect HTTP to HTTPS** — never serve sensitive content on port 80

**References:**
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [Prismor](https://github.com/PrismorSec/prismor)
