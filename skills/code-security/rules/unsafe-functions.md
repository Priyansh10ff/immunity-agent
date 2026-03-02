---
title: Avoid Unsafe Functions
impact: HIGH
impactDescription: Unsafe functions with no bounds checking lead to buffer overflows, memory corruption, and arbitrary code execution
tags: security, unsafe-functions, memory, c, cpp, cwe-120, cwe-676
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## Avoid Unsafe Functions

Certain functions in various programming languages are inherently dangerous because they do not perform boundary checks, can lead to buffer overflows, have been deprecated, or bypass type safety mechanisms. Using these functions can result in security vulnerabilities, memory corruption, and arbitrary code execution.

---

### C — Unsafe String Functions

**Incorrect (strcat — no bounds checking):**
```c
int bad_strcpy(src, dst) {
    strcat(dst, src);    // VULNERABLE: no bounds check
    strncat(dst, src, 100);  // Also vulnerable if n is not properly bounded
}
```

**Correct (use strcat_s with bounds checking):**
```c
strcat_s(dst, DST_BUFFER_SIZE, src);  // Safe: fails if result exceeds size
```

---

**Incorrect (strcpy — no bounds checking):**
```c
int bad_strcpy(src, dst) {
    strcpy(dst, src);    // VULNERABLE
    strncpy(dst, src, 100);  // Vulnerable if buffer < 100 and dst not null-terminated
}
```

**Correct:**
```c
strcpy_s(dst, DST_BUFFER_SIZE, src);  // Safe
```

---

**Incorrect (strtok — modifies buffer, not thread-safe):**
```c
int bad_code() {
    char str[DST_BUFFER_SIZE];
    fgets(str, DST_BUFFER_SIZE, stdin);
    strtok(str, " ");  // VULNERABLE: not thread-safe, modifies str
    printf("%s", str);
    return 0;
}
```

**Correct (use strtok_r — reentrant version):**
```c
int main() {
    char str[DST_BUFFER_SIZE];
    char *dest;
    fgets(str, DST_BUFFER_SIZE, stdin);
    strtok_r(str, " ", &dest);  // Safe: reentrant
    printf("%s", str);
    return 0;
}
```

---

**Incorrect (scanf — unbounded string read):**
```c
int bad_code() {
    char str[64];
    scanf("%s", str);  // VULNERABLE: reads unlimited bytes into 64-byte buffer
    printf("%s", str);
    return 0;
}
```

**Correct (fgets or bounded scanf):**
```c
int main() {
    char str[64];
    fgets(str, sizeof(str), stdin);  // Safe: bounded read
    printf("%s", str);
    return 0;
}
```

---

**Incorrect (gets — never safe, removed from C11):**
```c
int bad_code() {
    char str[64];
    gets(str);  // VULNERABLE: no bounds — removed from C11 standard
    printf("%s", str);
    return 0;
}
```

**Correct:**
```c
int main() {
    char str[64];
    fgets(str, sizeof(str), stdin);  // Safe
    printf("%s", str);
    return 0;
}
```

---

### PHP — Deprecated Crypto (mcrypt)

**Incorrect (deprecated mcrypt functions):**
```php
<?php
mcrypt_ecb(MCRYPT_BLOWFISH, $key, base64_decode($input), MCRYPT_DECRYPT);  // VULNERABLE
mcrypt_create_iv($iv_size, MCRYPT_RAND);  // VULNERABLE: deprecated
mdecrypt_generic($td, $c_t);  // VULNERABLE
```

**Correct (use Sodium or OpenSSL):**
```php
<?php
sodium_crypto_secretbox("Hello World!", $nonce, $key);  // Safe
openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv, $tag);  // Safe
```

---

### Python — Insecure Tempfile

**Incorrect (tempfile.mktemp — race condition):**
```python
import tempfile

x = tempfile.mktemp()        # VULNERABLE: path returned before file is created — TOCTOU
x = tempfile.mktemp(dir="/tmp")  # VULNERABLE
```

**Correct (NamedTemporaryFile — atomic creation):**
```python
import tempfile

with tempfile.NamedTemporaryFile() as tmp:
    tmp.write(b"data")  # Safe: file created and opened atomically
```

---

### Go — unsafe Package

**Incorrect (unsafe package bypasses type safety):**
```go
import "unsafe"

// VULNERABLE: bypasses Go's type system and memory safety guarantees
addressHolder := uintptr(unsafe.Pointer(intPtr)) + unsafe.Sizeof(intArray[0])
intPtr = (*int)(unsafe.Pointer(addressHolder))
```

**Correct (avoid the unsafe package):**
```go
// Use Go's type-safe alternatives for memory operations
// If you must use unsafe, limit scope and document clearly with security review requirement
```

---

## Unsafe Function Quick Reference

| Language | Avoid | Use Instead |
|----------|-------|-------------|
| C | `strcpy`, `strcat`, `gets`, `scanf("%s")` | `strcpy_s`, `strcat_s`, `fgets`, bounded `scanf` |
| C | `strtok` | `strtok_r` (reentrant) |
| C | `sprintf` | `snprintf` |
| PHP | `mcrypt_*` | `sodium_*`, `openssl_*` |
| Python | `tempfile.mktemp()` | `tempfile.NamedTemporaryFile()` |
| Go | `unsafe.Pointer` arithmetic | Type-safe operations |
| Rust | `unsafe {}` blocks | Safe Rust equivalents |

**References:**
- [CWE-120: Buffer Copy without Checking Size](https://cwe.mitre.org/data/definitions/120.html)
- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- [Semgrep Skills](https://github.com/semgrep/skills)
