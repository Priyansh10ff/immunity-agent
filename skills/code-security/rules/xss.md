---
title: Prevent Cross-Site Scripting (XSS)
impact: CRITICAL
impactDescription: Attackers can inject malicious scripts into web pages viewed by other users, stealing session tokens and user data
tags: security, xss, cwe-79, owasp-a03
attribution: Curated and enhanced for Prismor
---

## Prevent Cross-Site Scripting (XSS)

XSS occurs when untrusted data is included in a web page without proper escaping, allowing attackers to run scripts in a victim's browser. Always escape output, use framework-provided protections, and apply a Content-Security-Policy header.

**Vulnerable patterns:** Directly inserting user input into HTML, unsanitized `.innerHTML`, raw `render_template_string`, `dangerouslySetInnerHTML` without sanitization.

---

### Python (Flask)

**Incorrect (raw Jinja2 with |safe):**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # VULNERABLE: |safe disables auto-escaping
    return render_template_string("<h1>Hello {{ name | safe }}</h1>", name=name)
```

**Correct (auto-escaping enabled — Jinja2 default):**

```python
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # Safe: auto-escaping on, no |safe filter
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
```

---

### JavaScript / Node.js

**Incorrect (setting innerHTML with user input):**

```javascript
function displayComment(userInput) {
    // VULNERABLE: innerHTML interprets HTML tags
    document.getElementById('comment').innerHTML = userInput;
}
```

**Correct (use textContent instead of innerHTML):**

```javascript
function displayComment(userInput) {
    // Safe: textContent never interprets as HTML
    document.getElementById('comment').textContent = userInput;
}
```

**Correct (sanitize with DOMPurify if HTML is required):**

```javascript
import DOMPurify from 'dompurify';

function displayRichComment(userInput) {
    const clean = DOMPurify.sanitize(userInput);
    document.getElementById('comment').innerHTML = clean;
}
```

---

### Java (Servlets / JSP)

**Incorrect (raw output without escaping):**

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    String name = req.getParameter("name");
    PrintWriter out = resp.getWriter();
    out.println("<h1>Hello " + name + "</h1>");  // VULNERABLE
}
```

**Correct (use OWASP Java Encoder):**

```java
import org.owasp.encoder.Encode;

protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    String name = req.getParameter("name");
    PrintWriter out = resp.getWriter();
    out.println("<h1>Hello " + Encode.forHtml(name) + "</h1>");  // Safe
}
```

---

### Go (html/template)

**Incorrect (using text/template instead of html/template):**

```go
import "text/template"  // VULNERABLE — no HTML escaping

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    t, _ := template.New("").Parse("<h1>Hello {{.}}</h1>")
    t.Execute(w, name)
}
```

**Correct (use html/template which auto-escapes):**

```go
import "html/template"  // Safe — escapes HTML automatically

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    t, _ := template.New("").Parse("<h1>Hello {{.}}</h1>")
    t.Execute(w, name)
}
```

---

### React (JavaScript)

**Incorrect (dangerouslySetInnerHTML with raw user data):**

```jsx
function Comment({ userContent }) {
    // VULNERABLE
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
}
```

**Correct (render as text, or sanitize before setting HTML):**

```jsx
import DOMPurify from 'dompurify';

function Comment({ userContent }) {
    // If plain text is sufficient:
    return <div>{userContent}</div>;  // React auto-escapes this

    // If rich HTML is required, sanitize first:
    // const clean = DOMPurify.sanitize(userContent);
    // return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

---

## Key Prevention Rules

1. **Escape all output** — use framework auto-escaping; never disable it with `|safe` or equivalent
2. **Use `textContent` not `innerHTML`** — avoid direct HTML injection in JavaScript
3. **Apply Content-Security-Policy** — restrict script sources via CSP headers
4. **Sanitize if HTML output is required** — use DOMPurify (JS) or OWASP Java Encoder
5. **Validate input** — reject unexpected characters as defense in depth

**References:**
- [CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [Prismor](https://github.com/PrismorSec/prismor)
