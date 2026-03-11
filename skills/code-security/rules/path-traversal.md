---
title: Prevent Path Traversal
impact: CRITICAL
impactDescription: Attackers can read or overwrite arbitrary files on the server, including credentials and configuration files
tags: security, path-traversal, cwe-22, owasp-a01
attribution: Curated and enhanced for Prismor
---

## Prevent Path Traversal

Path traversal (also known as directory traversal) occurs when user-supplied input is used to construct file paths without proper validation. Attackers use sequences like `../` to escape the intended directory and access sensitive files such as `/etc/passwd`, private keys, or application configs.

**Vulnerable patterns:** Directly concatenating user input with file paths, using `open()` or `readFile()` with unsanitized filenames, not canonicalizing paths before checking them.

---

### Python

**Incorrect (direct path concatenation):**

```python
import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"

@app.route("/file")
def get_file():
    filename = request.args.get("name")
    path = os.path.join(BASE_DIR, filename)  # VULNERABLE: ../../../etc/passwd works
    return send_file(path)
```

**Correct (canonicalize and validate against base directory):**

```python
import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE_DIR = os.path.realpath("/var/www/uploads")

@app.route("/file")
def get_file():
    filename = request.args.get("name", "")
    # Resolve the full real path
    requested = os.path.realpath(os.path.join(BASE_DIR, filename))
    # Ensure the resolved path is still inside BASE_DIR
    if not requested.startswith(BASE_DIR + os.sep):
        abort(403)
    return send_file(requested)
```

---

### JavaScript / Node.js

**Incorrect (path.join without validation):**

```javascript
const path = require('path');
const fs = require('fs');
const express = require('express');
const app = express();

const BASE_DIR = '/var/www/uploads';

app.get('/file', (req, res) => {
    const filename = req.query.name;
    const filePath = path.join(BASE_DIR, filename);  // VULNERABLE
    res.sendFile(filePath);
});
```

**Correct (resolve and check prefix):**

```javascript
const path = require('path');
const fs = require('fs');
const express = require('express');
const app = express();

const BASE_DIR = path.resolve('/var/www/uploads');

app.get('/file', (req, res) => {
    const filename = req.query.name || '';
    const filePath = path.resolve(BASE_DIR, filename);

    // Ensure resolved path is within base directory
    if (!filePath.startsWith(BASE_DIR + path.sep)) {
        return res.status(403).send('Forbidden');
    }
    res.sendFile(filePath);
});
```

---

### Java

**Incorrect (using user input directly as file path):**

```java
@GetMapping("/file")
public ResponseEntity<byte[]> getFile(@RequestParam String filename) throws IOException {
    Path filePath = Paths.get("/var/www/uploads/" + filename);  // VULNERABLE
    byte[] content = Files.readAllBytes(filePath);
    return ResponseEntity.ok(content);
}
```

**Correct (normalize and validate path):**

```java
@GetMapping("/file")
public ResponseEntity<byte[]> getFile(@RequestParam String filename) throws IOException {
    Path baseDir = Paths.get("/var/www/uploads").normalize().toAbsolutePath();
    Path filePath = baseDir.resolve(filename).normalize().toAbsolutePath();

    // Ensure file is within base directory
    if (!filePath.startsWith(baseDir)) {
        return ResponseEntity.status(403).build();
    }
    byte[] content = Files.readAllBytes(filePath);
    return ResponseEntity.ok(content);
}
```

---

### Go

**Incorrect (direct filepath construction):**

```go
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("name")
    filePath := "/var/www/uploads/" + filename  // VULNERABLE
    http.ServeFile(w, r, filePath)
}
```

**Correct (use filepath.Clean and validate):**

```go
func serveFile(w http.ResponseWriter, r *http.Request) {
    baseDir := "/var/www/uploads"
    filename := r.URL.Query().Get("name")

    // Clean and build full path
    fullPath := filepath.Join(baseDir, filepath.Clean("/"+filename))

    // Validate it's within base directory
    if !strings.HasPrefix(fullPath, baseDir+string(os.PathSeparator)) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, fullPath)
}
```

---

## Key Prevention Rules

1. **Canonicalize paths** — always use `realpath()` / `.normalize()` / `path.resolve()` before checking
2. **Check prefix after canonicalization** — `../` sequences are resolved before the check
3. **Use allowlists** — if possible, accept only known, pre-approved filenames and map them to paths server-side
4. **Never expose raw filesystem paths in responses** — avoid leaking directory structure
5. **Set proper file permissions** — defense in depth if traversal does occur

**References:**
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [Prismor](https://github.com/PrismorSec/prismor)
