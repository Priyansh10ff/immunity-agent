---
title: Prevent Command Injection
impact: CRITICAL
impactDescription: Remote code execution allowing attackers to run arbitrary commands on the host system
tags: security, command-injection, cwe-78, cwe-94
attribution: Curated and enhanced for Prismor
---

## Prevent Command Injection

Command injection occurs when untrusted input is passed to system shell commands. Attackers can execute arbitrary commands on the host system, potentially downloading malware, stealing data, or taking complete control of the server.

---

### Python

**Incorrect (vulnerable to command injection via subprocess):**

```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    ip = flask.request.args.get("ip")
    subprocess.run("ping " + ip, shell=True)  # VULNERABLE: shell=True + user input
```

**Correct (use array form without shell=True):**

```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    ip = flask.request.args.get("ip")
    subprocess.run(["ping", ip])  # Safe: no shell, arguments are separate
```

---

### JavaScript / Node.js

**Incorrect (vulnerable child_process with user input):**

```javascript
const { exec } = require('child_process');

function runCommand(userInput) {
    exec(`cat ${userInput}`, (error, stdout, stderr) => {  // VULNERABLE
        console.log(stdout);
    });
}
```

**Correct (use spawn with array arguments):**

```javascript
const { spawn } = require('child_process');

function runCommand(userInput) {
    const proc = spawn('cat', [userInput]);  // Safe: no shell interpolation
    proc.stdout.on('data', (data) => {
        console.log(data.toString());
    });
}
```

---

### Java

**Incorrect (ProcessBuilder with user input via shell):**

```java
public class CommandRunner {
    public void runCommand(String userInput) throws IOException {
        String[] cmd = {"/bin/bash", "-c", userInput};  // VULNERABLE
        ProcessBuilder builder = new ProcessBuilder(cmd);
        Process proc = builder.start();
    }
}
```

**Correct (use ProcessBuilder with explicit arguments, no shell):**

```java
public class CommandRunner {
    public void runCommand(String filename) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("cat", filename);  // Safe
        Process proc = builder.start();
    }
}
```

---

### Go

**Incorrect (dangerous command with user input via stdin):**

```go
func runCommand(userInput string) {
    cmd := exec.Command("bash")
    cmdWriter, _ := cmd.StdinPipe()
    cmd.Start()
    cmdString := fmt.Sprintf("echo %s", userInput)  // VULNERABLE
    cmdWriter.Write([]byte(cmdString + "\n"))
    cmd.Wait()
}
```

**Correct (use exec.Command with explicit arguments):**

```go
func runCommand(filename string) {
    cmd := exec.Command("cat", filename)  // Safe: arguments never go through shell
    output, _ := cmd.Output()
    println(string(output))
}
```

---

### Ruby

**Incorrect (shell methods with tainted input):**

```ruby
def read_file(params)
    Shell.cat(params[:filename])  # VULNERABLE if params is user-controlled
end
```

**Correct (use hardcoded or validated paths):**

```ruby
ALLOWED_FILES = ["/var/log/www/access.log", "/var/log/www/error.log"].freeze

def read_file(requested)
    path = ALLOWED_FILES.find { |f| f == requested }
    raise "Unauthorized" unless path
    Shell.cat(path)
end
```

---

## Key Prevention Rules

1. **Never pass user input to shell commands** — no `shell=True`, no shell interpolation
2. **Use array-form exec APIs** — each argument is passed separately, never interpreted by the shell
3. **Validate inputs against an allowlist** — if you must run commands, validate the input strictly
4. **Prefer language-native alternatives** — use library functions (e.g., `os.listdir()`) instead of `ls`
5. **Run with least privilege** — ensure the process running these commands has minimal OS permissions

**References:**
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection)
- [Prismor](https://github.com/PrismorSec/prismor)
