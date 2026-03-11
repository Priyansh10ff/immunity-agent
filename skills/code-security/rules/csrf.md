---
title: Prevent Cross-Site Request Forgery (CSRF)
impact: HIGH
impactDescription: Attackers force authenticated users to perform unwanted actions without their knowledge
tags: security, csrf, cwe-352, owasp-a01
attribution: Curated and enhanced for Prismor
---

## Prevent Cross-Site Request Forgery (CSRF)

CSRF attacks force authenticated users to execute unwanted state-changing actions on a web application. Since browsers automatically include session cookies with requests, attackers can craft malicious pages that trigger API calls as the victim without their knowledge.

**Vulnerable patterns:** Disabling CSRF middleware, using `@csrf_exempt`, not calling `protect_from_forgery`.

---

### Python / Django

**Incorrect (`@csrf_exempt` disables CSRF protection):**
```python
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # VULNERABLE: removes CSRF protection from this view
def my_view(request):
    return HttpResponse('Hello world')
```

**Correct (remove the decorator — Django enables protection by default):**
```python
from django.http import HttpResponse

def my_view(request):
    return HttpResponse('Hello world')  # Safe: Django's CsrfViewMiddleware applies
```

**References:**
- [Django CSRF Protection Documentation](https://docs.djangoproject.com/en/stable/ref/csrf/)

---

### JavaScript / Express

**Incorrect (no CSRF middleware):**
```javascript
var express = require('express')
var bodyParser = require('body-parser')

var app = express()

app.post('/process', bodyParser.urlencoded({ extended: false }), function(req, res) {
    res.send('data is being processed')  // VULNERABLE: no CSRF token required
})
```

**Correct (use csurf middleware):**
```javascript
var csrf = require('csurf')
var express = require('express')

var app = express()
app.use(csrf({ cookie: true }))  // Safe: requires valid CSRF token on state-changing requests
```

**References:**
- [csurf npm package](https://www.npmjs.com/package/csurf)

---

### Java / Spring Security

**Incorrect (explicitly disabling CSRF):**
```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()  // VULNERABLE: disables CSRF protection globally
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated();
    }
}
```

**Correct (CSRF protection enabled by default — just don't disable it):**
```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated();
        // Spring Security enables CSRF by default — no need to configure it
    }
}
```

---

### Ruby / Rails

**Incorrect (controller without protect_from_forgery):**
```ruby
class DangerousController < ActionController::Base
    # VULNERABLE: no CSRF protection
    puts "do more stuff"
end
```

**Correct (include protect_from_forgery):**
```ruby
class SafeController < ActionController::Base
    protect_from_forgery with: :exception

    puts "do more stuff"
end
```

**References:**
- [Rails ActionController RequestForgeryProtection](https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection/ClassMethods.html)

---

## Key Prevention Rules

1. **Use CSRF tokens** — require a unique, secret, unpredictable token on every state-changing request
2. **Never disable CSRF middleware** — `@csrf_exempt`, `.csrf().disable()`, removing `protect_from_forgery` all create vulnerabilities
3. **Use SameSite cookies** — set `SameSite=Strict` or `SameSite=Lax` on session cookies as defense in depth
4. **Verify Origin/Referer headers** — for APIs, validate that request origin matches expected domain
5. **Exempt only truly stateless endpoints** — REST APIs using tokens (not cookies) may be exempt, but cookie-authenticated endpoints must have CSRF protection

**References:**
- [CWE-352: CSRF](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Prismor](https://github.com/PrismorSec/prismor)
