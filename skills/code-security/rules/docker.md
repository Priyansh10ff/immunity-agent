---
title: Secure Docker Configurations
impact: HIGH
impactDescription: Insecure Dockerfiles and daemon configurations enable container breakouts and image poisoning
tags: security, docker, containers, infrastructure, cicd
attribution: Curated and enhanced for Prismor
---

## Secure Docker Configurations

Best practices for writing secure Dockerfiles and configuring the Docker daemon.

---

### Run as Non-Root User

Running as root inside a container makes it trivial to escape to the host if a vulnerability is found.

**Incorrect:**
```dockerfile
FROM alpine:3.18
RUN apk add --no-cache curl
# Running as root by default
CMD ["curl", "https://example.com"]
```

**Correct:**
```dockerfile
FROM alpine:3.18
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
RUN apk add --no-cache curl
CMD ["curl", "https://example.com"]
```

---

### Use Trusted and Minimal Base Images

Large base images contain unnecessary tools (shells, package managers) that aid attackers.

**Incorrect:**
```dockerfile
FROM ubuntu:latest  # Untrusted versioning, large attack surface
```

**Correct:**
```dockerfile
FROM alpine:3.18.5@sha256:34871...  # Pinned by version and digest
```

---

### Don't Store Secrets in Build Args or Environment Variables

Secrets in ENV or ARG are baked into the image layers and can be retrieved with `docker history`.

**Incorrect:**
```dockerfile
FROM python:3.11
ENV DB_PASSWORD=secret_password  # VULNERABLE
```

**Correct (use Docker Secrets or BuildKit mounts):**
```dockerfile
# Use BuildKit mount for secrets (never stored in image)
RUN --mount=type=secret,id=my_secret \
    export PASSWORD=$(cat /run/secrets/my_secret) && \
    ./install.sh
```

---

### Avoid SSH in Containers

**Incorrect:**
```dockerfile
RUN apt-get install openssh-server -y  # VULNERABLE: increases attack surface
```

**Correct:**
```dockerfile
# Use 'docker exec' for debugging, never install SSH
```

---

## Key Prevention Rules

1. **User `USER` directive** — Always switch to a non-privileged user.
2. **Pin images by digest** — Use `@sha256:...` to ensure image integrity.
3. **Use `.dockerignore`** — Prevent sensitive local files (e.g., `.env`, `.git`) from being copied into the image.
4. **Scan images for vulnerabilities** — Use `docker scan` or tools like Trivy/Grype.
5. **No privileged mode** — Never run containers with `--privileged`.

**References:**
- [Docker Security Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Prismor](https://github.com/PrismorSec/prismor)
