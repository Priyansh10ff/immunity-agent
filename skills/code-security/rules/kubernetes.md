---
title: Secure Kubernetes Configurations
impact: HIGH
impactDescription: Kubernetes misconfigurations enable container escapes, privilege escalation, and host compromise
tags: security, kubernetes, containers, infrastructure, cwe-250
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## Secure Kubernetes Configurations

Security best practices for Kubernetes YAML configurations. Containers should run with minimal permissions as non-root users, host namespaces should not be shared, and secrets must never be stored in plaintext config files.

---

### Privileged Containers

Running privileged containers grants full host access — treat it like giving root on the node.

**Incorrect:**
```yaml
spec:
  containers:
    - name: nginx
      image: nginx
      securityContext:
        privileged: true  # VULNERABLE: full host access
```

**Correct:**
```yaml
spec:
  containers:
    - name: nginx
      image: nginx
      securityContext:
        privileged: false
```

---

### Run as Non-Root

**Incorrect:**
```yaml
spec:
  securityContext:
    runAsNonRoot: false  # VULNERABLE: permits root execution
  containers:
    - name: redis
      image: redis
```

**Correct:**
```yaml
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: nginx
      image: nginx
```

---

### Prevent Privilege Escalation

**Incorrect:**
```yaml
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        allowPrivilegeEscalation: true  # VULNERABLE
```

**Correct:**
```yaml
spec:
  containers:
    - name: haproxy
      image: haproxy
      securityContext:
        allowPrivilegeEscalation: false
```

---

### Host PID / Network / IPC Namespaces

Sharing host namespaces allows containers to see all host processes, network interfaces, or shared memory.

**Incorrect:**
```yaml
spec:
  hostPID: true      # VULNERABLE
  hostNetwork: true  # VULNERABLE
  hostIPC: true      # VULNERABLE
  containers:
    - name: nginx
      image: nginx
```

**Correct:**
```yaml
spec:
  # hostPID, hostNetwork, hostIPC default to false — just don't set them
  containers:
    - name: nginx
      image: nginx
```

---

### Docker Socket Exposure

Mounting the Docker socket gives a container full control over the Docker daemon — equivalent to root on the host.

**Incorrect:**
```yaml
spec:
  containers:
    - name: test-container
      volumeMounts:
        - mountPath: /var/run/docker.sock
          name: docker-sock-volume  # VULNERABLE
  volumes:
    - name: docker-sock-volume
      hostPath:
        type: File
        path: /var/run/docker.sock
```

**Correct:**
```yaml
spec:
  containers:
    - name: test-container
      volumeMounts:
        - mountPath: /data
          name: data-volume
  volumes:
    - name: data-volume
      emptyDir: {}
```

---

### Secrets Management — No Plaintext in ConfigMaps

**Incorrect (base64 is not encryption):**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  USERNAME: Y2FsZWJraW5uZXk=  # Just base64 — anyone with kubectl can decode
  PASSWORD: UzNjcmV0UGEkJHcwcmQ=
```

**Correct (use Sealed Secrets or external secrets operator):**
```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mysecret
spec:
  encryptedData:
    password: AgBy8hCi8...encrypted...
```

---

### Pinned Image Versions

**Incorrect:**
```yaml
spec:
  containers:
    - image: nginx         # VULNERABLE: uses latest by default
    - image: redis:latest  # VULNERABLE: non-deterministic builds
```

**Correct:**
```yaml
spec:
  containers:
    - image: nginx:1.25.3
    - image: redis:7.2.4
```

---

## Key Prevention Rules

1. **Never run privileged containers** — `privileged: false` in every securityContext
2. **Always run as non-root** — `runAsNonRoot: true` at pod or container level
3. **Block privilege escalation** — `allowPrivilegeEscalation: false` always
4. **Don't share host namespaces** — `hostPID`, `hostNetwork`, `hostIPC` must all be `false`
5. **Never mount the Docker socket** — this grants full host control
6. **Use encrypted secrets** — Sealed Secrets, AWS Secrets Manager CSI driver, or Vault
7. **Pin image versions** — use specific tags or digests, never `latest`

**References:**
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Semgrep Skills](https://github.com/semgrep/skills)
