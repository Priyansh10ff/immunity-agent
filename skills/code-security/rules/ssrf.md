---
title: Prevent Server-Side Request Forgery (SSRF)
impact: HIGH
impactDescription: Attackers can force the server to make requests to internal services, cloud metadata APIs, and other restricted resources
tags: security, ssrf, cwe-918, owasp-a10
attribution: Curated and enhanced for Prismor
---

## Prevent Server-Side Request Forgery (SSRF)

SSRF occurs when a server makes outbound HTTP requests to URLs provided or influenced by user input. Attackers use this to reach internal services that are not publicly accessible, including cloud instance metadata endpoints (e.g., `http://169.254.169.254`), internal admin panels, and databases.

**Vulnerable patterns:** Directly passing user-supplied URLs to `requests.get()`, `fetch()`, `http.Get()`, or similar HTTP client functions.

---

### Python

**Incorrect (fetch any user-provided URL):**

```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    resp = requests.get(url)  # VULNERABLE: attacker can supply internal URLs
    return resp.text
```

**Correct (validate URL against an allowlist):**

```python
import requests
from urllib.parse import urlparse
from flask import Flask, request, abort

app = Flask(__name__)

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        # Only allow https, and only to allowlisted hosts
        if parsed.scheme != "https":
            return False
        if parsed.hostname not in ALLOWED_HOSTS:
            return False
        return True
    except Exception:
        return False

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if not is_safe_url(url):
        abort(400)
    resp = requests.get(url, timeout=5)
    return resp.text
```

---

### JavaScript / Node.js

**Incorrect (direct fetch with user URL):**

```javascript
const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.get('/proxy', async (req, res) => {
    const { url } = req.query;
    const response = await fetch(url);  // VULNERABLE
    const data = await response.text();
    res.send(data);
});
```

**Correct (allowlist validation):**

```javascript
const { URL } = require('url');

const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

function isSafeUrl(rawUrl) {
    try {
        const parsed = new URL(rawUrl);
        return parsed.protocol === 'https:' && ALLOWED_HOSTS.has(parsed.hostname);
    } catch {
        return false;
    }
}

app.get('/proxy', async (req, res) => {
    const { url } = req.query;
    if (!isSafeUrl(url)) {
        return res.status(400).send('URL not permitted');
    }
    const response = await fetch(url, { timeout: 5000 });
    const data = await response.text();
    res.send(data);
});
```

---

### Go

**Incorrect (http.Get with user-supplied URL):**

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    resp, err := http.Get(targetURL)  // VULNERABLE
    if err != nil {
        http.Error(w, "Error", 500)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
```

**Correct (parse and validate before requesting):**

```go
var allowedHosts = map[string]bool{
    "api.example.com": true,
    "cdn.example.com": true,
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
    rawURL := r.URL.Query().Get("url")
    parsed, err := url.Parse(rawURL)
    if err != nil || parsed.Scheme != "https" || !allowedHosts[parsed.Hostname()] {
        http.Error(w, "URL not permitted", http.StatusBadRequest)
        return
    }

    resp, err := http.Get(parsed.String())
    if err != nil {
        http.Error(w, "Error", 500)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
```

---

## Key Prevention Rules

1. **Use URL allowlists** — only permit requests to explicitly approved hostnames
2. **Block private IP ranges** — reject requests to `10.x.x.x`, `172.16.x.x`, `192.168.x.x`, `127.x.x.x`, `169.254.x.x` (cloud metadata)
3. **Enforce HTTPS** — never allow plain `http://` for proxied requests
4. **Validate after DNS resolution** — re-check the resolved IP is not internal (DNS rebinding prevention)
5. **Set timeouts** — always set short connect and read timeouts on proxied HTTP calls
6. **Never return raw response bodies** — avoid leaking internal service responses to the user

**Common SSRF Targets to Block:**

| Target | Risk |
|--------|------|
| `http://169.254.169.254/` | AWS/GCP/Azure instance metadata |
| `http://localhost/` | Server's own services |
| `http://10.0.0.0/8` | Internal network |
| `file:///etc/passwd` | Local file read via URL |

**References:**
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP A10:2021 SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [Prismor](https://github.com/PrismorSec/prismor)
