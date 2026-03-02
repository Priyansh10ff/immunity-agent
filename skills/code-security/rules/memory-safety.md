---
title: Ensure Memory Safety
impact: CRITICAL
impactDescription: Memory vulnerabilities in C/C++ lead to arbitrary code execution, data corruption, and denial of service
tags: security, memory-safety, buffer-overflow, c, cpp, cwe-415, cwe-416, cwe-119
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## Ensure Memory Safety

Memory safety vulnerabilities are among the most critical security issues in C/C++ software. They can lead to arbitrary code execution, data corruption, denial of service, and information disclosure. This guide covers double-free, use-after-free, buffer overflow, and format string vulnerabilities.

---

### Double Free (CWE-415)

Freeing memory twice can cause memory corruption, crashes, or allow attackers to execute arbitrary code.

**Incorrect:**
```c
int bad_code() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    free(var);  // VULNERABLE: double free
    return 0;
}
```

**Correct (set pointer to NULL after free):**
```c
int safe_code() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    var = NULL;   // Prevent double-free and use-after-free
    free(var);    // Safe: freeing NULL is a no-op
    return 0;
}
```

---

### Use After Free (CWE-416)

Accessing memory after it has been freed can lead to crashes, data corruption, or code execution.

**Incorrect:**
```c
typedef struct name {
    char *myname;
    void (*func)(char *str);
} NAME;

int bad_code() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var->func("use after free");  // VULNERABLE: accessing freed memory
    return 0;
}
```

**Correct:**
```c
int safe_code() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = NULL;  // Any subsequent access will cause immediate crash (easier to debug)
    return 0;
}
```

---

### Buffer Overflow (CWE-119, CWE-120)

Writing beyond buffer boundaries can overwrite adjacent memory, causing crashes or code execution.

**Incorrect (strcpy — no bounds check):**
```c
void bad_code(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // VULNERABLE: no length limit
}
```

**Correct (strncpy with explicit null termination):**
```c
void safe_code(char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Always null-terminate explicitly
}
```

---

### Format String Vulnerabilities (CWE-134)

Using user-controlled format strings allows attackers to read or write arbitrary memory.

**Incorrect:**
```c
void bad_printf(char *user_input) {
    printf(user_input);  // VULNERABLE: user controls format string — %n writes to memory
}
```

**Correct:**
```c
void safe_printf(char *user_input) {
    printf("%s", user_input);  // Safe: format string is a hardcoded literal
}
```

---

## Prevention Best Practices

1. **Set pointers to NULL after freeing** — prevents use-after-free and double-free
2. **Use bounded string functions** — `strncpy`, `snprintf` instead of `strcpy`, `sprintf`; prefer `strncpy_s` / `snprintf`
3. **Never use user input as format strings** — always use a fixed format string literal
4. **Validate array indices** — explicitly check bounds before accessing arrays
5. **Use static analysis tools** — Semgrep, Coverity, AddressSanitizer, Valgrind
6. **Consider memory-safe languages** — Rust, Go, or managed languages eliminate entire classes of memory bugs

**Unsafe functions to avoid:**

| Unsafe | Safe alternative |
|--------|-----------------|
| `strcpy` | `strncpy` + null-terminate, or `strcpy_s` |
| `strcat` | `strncat` + length check, or `strcat_s` |
| `gets` | `fgets` |
| `scanf("%s")` | `scanf("%63s")` with width limit, or `fgets` |
| `sprintf` | `snprintf` with size |
| `printf(user_str)` | `printf("%s", user_str)` |

**References:**
- [CWE-119: Buffer Overflow](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-415: Double Free](https://cwe.mitre.org/data/definitions/415.html)
- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [Semgrep Skills](https://github.com/semgrep/skills)
