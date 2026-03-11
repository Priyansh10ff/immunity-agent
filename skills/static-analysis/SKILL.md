---
name: static-analysis
version: 1.0.0
description: "Static-analysis guidance for pattern-based security scans and custom detection rules. Use when scanning code for security bugs, creating custom static-analysis rules, enforcing secure coding patterns, or adding machine-checkable checks to Prismor or downstream repositories. Also use when users ask to audit code, scan for vulnerabilities, or write a custom detection rule."
homepage: https://github.com/PrismorSec/prismor
metadata: {"openclaw":{"emoji":"🛡️","category":"security"}}
---

# Static Analysis

Use this skill when the task involves static-analysis scans, custom detection rule authoring, or pattern-based vulnerability detection.

## When To Use

Use this skill when:

- scanning code for known security issues
- writing custom detection rules
- enforcing secure coding patterns across repositories
- validating that code changes match Prismor guidance
- auditing code for OWASP or CWE-style bug patterns

## Core Workflow

1. Decide whether the task is:
   - running an existing static-analysis scan
   - creating a custom rule
   - validating a new rule
2. Prefer pattern-based static analysis when you need fast detection across many files.
3. Prefer source-to-sink analysis for injection-style issues.
4. Test custom rules with explicit positive and negative cases.

## Running Scans

Quick scan:

```bash
<static-analysis-tool> --config auto .
```

Security-focused scan:

```bash
<static-analysis-tool> --config security-audit .
```

OWASP-oriented scan:

```bash
<static-analysis-tool> --config owasp-top-ten .
```

JSON output:

```bash
<static-analysis-tool> --config security-audit --json -o results.json .
```

SARIF output:

```bash
<static-analysis-tool> --config security-audit --sarif -o results.sarif .
```

Replace `<static-analysis-tool>` with the scanner available in the environment.

## Ruleset Selection

Use these defaults:

- a broad security-audit ruleset for general security review
- an OWASP-oriented ruleset for web-application risk patterns
- a CWE-oriented ruleset for common weakness coverage
- automatic detection for a fast first pass

## Writing Custom Rules

Choose the rule approach first:

- use pattern matching for syntax-only patterns
- use taint or dataflow mode when untrusted input must not reach a dangerous sink

Pattern rule example:

```yaml
rules:
  - id: hardcoded-password
    languages: [python]
    message: Hardcoded password detected
    severity: ERROR
    pattern: password = "$PASSWORD"
```

Dataflow-oriented example:

```yaml
rules:
  - id: command-injection
    languages: [python]
    message: User input flows to command execution
    severity: ERROR
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: os.system(...)
      - pattern: subprocess.call($CMD, shell=True, ...)
    pattern-sanitizers:
      - pattern: shlex.quote(...)
```

## Rule Testing

Create tests before finalizing a rule:

```python
def vulnerable():
    user_input = request.args.get("id")
    # ruleid: my-rule
    os.system(user_input)

def safe():
    user_input = request.args.get("id")
    # ok: my-rule
    os.system(shlex.quote(user_input))
```

Run the equivalent validate and test commands for the scanner in use, and do not claim the rule works until those tests pass cleanly.

## How This Fits Prismor

Use static analysis as the machine-checkable complement to Prismor:

- Prismor skills define secure behavior and review expectations
- Prismor feed provides current AI-security threat context
- Warden protects live agent sessions
- static analysis helps detect code patterns and enforce rules in codebases

Use it when you want machine-checkable enforcement of the secure coding guidance already described in:

- `skills/code-security/SKILL.md`
- `skills/llm-security/SKILL.md`

## Practical Guidance For Agents

- start with existing rulesets before inventing custom ones
- use dataflow or taint analysis for injection classes
- keep rules specific enough to avoid noisy false positives
- include safe examples in tests, not only vulnerable ones
- prefer scanners that can emit SARIF or JSON for CI integration
