---
title: Prevent Prototype Pollution
impact: HIGH
impactDescription: Attackers can modify Object.prototype to inject properties that exist on every object, enabling privilege escalation
tags: security, prototype-pollution, javascript, cwe-915
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## Prevent Prototype Pollution

Prototype pollution occurs when an attacker can modify `Object.prototype` by assigning to specially crafted keys like `__proto__`, `constructor`, or `prototype` through user-supplied data. Properties added to `Object.prototype` are inherited by every plain object in the application, enabling logic bypasses and privilege escalation.

**Attack vector:** `obj[userKey] = userValue` where the key is `__proto__` or `constructor.prototype`.

---

### Dynamic Property Assignment from User Input

**Incorrect (user controls key name — enables `__proto__` injection):**
```javascript
app.get('/test/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    items[req.query.name] = req.query.text;  // VULNERABLE: name could be "__proto__"
    res.end(200);
});
```

**Correct (validate against dangerous keys):**
```javascript
app.post('/test/:id', (req, res) => {
    let id = req.params.id;
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    if (dangerousKeys.includes(id) || dangerousKeys.includes(req.query.name)) {
        return res.status(400).send('Invalid key');
    }
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    items[req.query.name] = req.query.text;
    res.end(200);
});
```

---

### Nested Property Assignment from User Input

**Incorrect (arbitrary nested path traversal via user-controlled keys):**
```javascript
function setNestedValue(obj, props, value) {
    props = props.split('.');
    var lastProp = props.pop();
    while ((thisProp = props.shift())) {
        if (typeof obj[thisProp] == 'undefined') {
            obj[thisProp] = {};
        }
        obj = obj[thisProp];  // VULNERABLE: traverses __proto__
    }
    obj[lastProp] = value;
}
```

**Correct (use numeric indices or Map):**
```javascript
// Use a Map instead of a plain object to avoid prototype chain
const config = new Map();

function safeSetValue(key, value) {
    // Validate key doesn't contain dangerous segments
    if (key.includes('__proto__') || key.includes('constructor')) {
        throw new Error('Invalid key');
    }
    config.set(key, value);
}
```

---

### Object.assign with User Input

**Incorrect (Object.assign with req.body — pollutes target):**
```javascript
function controller(req, res) {
    const defaultData = { foo: true }
    let data = Object.assign(defaultData, req.body)  // VULNERABLE: req.body may contain __proto__
    doSmthWith(data)
}
```

**Correct (use trusted data, not raw request body):**
```javascript
function controller(req, res) {
    const defaultData = { foo: { bar: true } }
    let data = Object.assign(defaultData, { foo: getTrustedFoo() })
    doSmthWith(data)
}
```

**Correct (use JSON parse with Object.create(null) for untrusted merges):**
```javascript
function safeMerge(target, untrustedSource) {
    const sanitized = JSON.parse(JSON.stringify(untrustedSource));  // Strips __proto__
    return Object.assign(target, sanitized);
}
```

---

## Key Prevention Rules

1. **Validate object keys** — reject `__proto__`, `constructor`, `prototype` (and their variants) before assigning
2. **Use `Object.create(null)`** — creates objects with no prototype chain, immune to pollution
3. **Use `Map` instead of plain objects** — Maps don't have the `__proto__` inheritance vulnerability
4. **Freeze prototypes** — call `Object.freeze(Object.prototype)` at application startup to prevent runtime modification
5. **Sanitize before merging** — `JSON.parse(JSON.stringify(input))` strips non-JSON-serializable prototype pollution attempts
6. **Use schema validation libraries** — Ajv or Joi with `allowUnknownFields: false` before deep-merging user data

**References:**
- [CWE-915: Prototype Pollution](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Snyk: Prototype Pollution](https://learn.snyk.io/lesson/prototype-pollution/)
- [Semgrep Skills](https://github.com/semgrep/skills)
