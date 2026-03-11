---
title: Prevent Code Injection
impact: CRITICAL
impactDescription: Remote code execution via eval/exec allows attackers to run arbitrary code
tags: security, code-injection, rce, cwe-94, cwe-95, owasp-a03
attribution: Curated and enhanced for Prismor
---

## Prevent Code Injection

Code injection occurs when an attacker can insert and execute arbitrary code within your application. This includes direct code evaluation (`eval`, `exec`), reflection-based attacks, and dynamic method invocation. These vulnerabilities can lead to complete system compromise, data theft, and remote code execution.

**Vulnerable patterns:** `eval(user_input)`, `exec(user_input)`, dynamic ScriptEngine evaluation with user data, `shell_exec($user_input)` in PHP.

---

### Python

**Incorrect (eval with user input — RCE):**
```python
def unsafe(request):
    code = request.POST.get('code')
    eval(code)  # VULNERABLE: attacker can run any Python code
```

**Correct (eval only with static strings, never user input):**
```python
# eval is safe only when the string is a hardcoded literal
eval("x = 1; x = x + 2")

# If you need dynamic computation, use ast.literal_eval for simple expressions:
import ast
def safe_eval(expression: str):
    return ast.literal_eval(expression)  # Only evaluates literals, not statements
```

---

### JavaScript

**Incorrect (eval with dynamic content):**
```javascript
let dynamic = window.prompt()
eval(dynamic + 'possibly malicious code');  // VULNERABLE

function evalSomething(something) {
    eval(something);  // VULNERABLE
}
```

**Correct (eval only with static strings):**
```javascript
// Only safe when the string is a hardcoded literal at call time
eval('var x = "static strings are okay";');

// Better: use JSON.parse for data, or structured function calls
const result = JSON.parse(userInput);  // Safe for data parsing
```

---

### Java (ScriptEngine)

**Incorrect (ScriptEngine with user input):**
```java
public class ScriptEngineSample {
    private static ScriptEngineManager sem = new ScriptEngineManager();
    private static ScriptEngine se = sem.getEngineByExtension("js");

    public static void scripting(String userInput) throws ScriptException {
        Object result = se.eval("test=1;" + userInput);  // VULNERABLE
    }
}
```

**Correct (only evaluate static strings):**
```java
public class ScriptEngineSample {
    public static void scriptingSafe() throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
        String code = "var test=3;test=test*2;";  // Hardcoded, not user-supplied
        Object result = scriptEngine.eval(code);
    }
}
```

---

### Ruby

**Incorrect (eval with user input):**
```ruby
b = params['something']
eval(b)  # VULNERABLE: executes arbitrary Ruby
eval(params['cmd'])  # VULNERABLE
```

**Correct (eval only with static strings):**
```ruby
eval("def zen; 42; end")  # Safe: hardcoded string
```

---

### PHP

**Incorrect (exec functions with user input):**
```php
exec($user_input);             // VULNERABLE
passthru($user_input);         // VULNERABLE
$output = shell_exec($user_input);  // VULNERABLE
$output = system($user_input, $retval);  // VULNERABLE

$username = $_COOKIE['username'];
exec("wto -n \"$username\" -g", $ret);  // VULNERABLE: command injection
```

**Correct (static commands; escape arguments if user data required):**
```php
exec('whoami');  // Safe: static command

$fullpath = $_POST['fullpath'];
$filesize = trim(shell_exec('stat -c %s ' . escapeshellarg($fullpath)));
// Note: escapeshellarg only escapes — avoid passing user input to exec at all if possible
```

---

## Key Prevention Rules

1. **Never pass user input to eval/exec** — treat all user input as untrusted
2. **Use static strings in eval** — if eval is necessary, only evaluate hardcoded literals
3. **Validate against a strict allowlist** — if dynamic computation is unavoidable, only allow specific, pre-approved operations
4. **Use parameterized alternatives** — expression parsers, JSON, or dedicated math libraries instead of eval
5. **Escape shell arguments** — use `escapeshellarg()` in PHP or equivalent, and prefer array-form subprocess APIs over shell strings

**References:**
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [MDN: Never use eval()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
- [Prismor](https://github.com/PrismorSec/prismor)
