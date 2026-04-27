# Week 11 — Container Security: Docker Hardening & Falco Runtime Detection

**Phase 3: Threat Detection & Response | Project: 10-container-security-framework**

---

## Learning Objectives

By the end of this week you will be able to:

- Apply the CIS Docker Benchmark Level 1 hardening steps to production Dockerfiles
- Scan container images for CVEs using Trivy and Grype
- Write custom Falco rules for runtime threat detection inside containers
- Implement non-root, read-only, capability-dropped container configurations
- Build a CI/CD gate that blocks deployment of images with CRITICAL vulnerabilities
- Understand the container attack surface: image, runtime, registry, orchestration

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Container security fundamentals — attack surface, namespaces, cgroups, capabilities | 2 hrs |
| Tue | CIS Docker Benchmark — host config, daemon config, image creation, runtime | 2 hrs |
| Wed | Image scanning with Trivy and Grype — install, scan, interpret results, SARIF output | 2 hrs |
| Thu | Falco installation and rule syntax — conditions, macros, lists, output | 2 hrs |
| Fri | Write 8 custom Falco rules + integrate into CI/CD pipeline | 2 hrs |
| Sat | Build hardened Dockerfile, GitHub Actions CI gate, push to GitHub | 3 hrs |
| Sun | Mentor review — container security interview prep | 1 hr |

---

## Topics Covered

### Container Attack Surface

```
┌─────────────────────────────────────────────────────────────┐
│ Container Attack Surface                                     │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Image      │    │   Runtime    │    │  Registry    │  │
│  │  • Base CVEs │    │  • Escapes   │    │  • Poisoned  │  │
│  │  • Secrets   │    │  • Root user │    │    images    │  │
│  │  • Malware   │    │  • Privesc   │    │  • No auth   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                              │
│  ┌──────────────┐    ┌──────────────────────────────────┐  │
│  │    Host      │    │         Orchestration            │  │
│  │  • Daemon    │    │  • Misconfigured RBAC            │  │
│  │    socket    │    │  • Privileged pods               │  │
│  │  • Kernel    │    │  • Exposed API server            │  │
│  └──────────────┘    └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Dangerous Container Patterns

```dockerfile
# DANGEROUS: Running as root
FROM ubuntu:latest
RUN apt-get install -y curl
# No USER instruction = runs as root

# DANGEROUS: Docker socket mounted
# docker run -v /var/run/docker.sock:/var/run/docker.sock myapp
# → attacker can escape to host via docker CLI
```

```yaml
# DANGEROUS: Privileged container
docker run --privileged myapp
# → has full access to host capabilities

# DANGEROUS: Capability over-grant
docker run --cap-add SYS_ADMIN myapp
# → can mount filesystems, access kernel
```

### CIS Docker Benchmark Key Controls

**Host Configuration:**
- 1.1 Ensure a separate partition for containers exists
- 1.2 Ensure only trusted users are in the docker group

**Docker Daemon:**
- 2.1 Ensure network traffic is restricted between containers
- 2.5 Ensure insecure registries are not used
- 2.14 Ensure user namespace support is enabled
- 2.18 Ensure default ulimit is configured appropriately

**Container Runtime:**
- 5.1 Ensure AppArmor/SELinux profile is applied
- 5.2 Ensure SELinux security options are set
- 5.3 Ensure Linux kernel capabilities are restricted
- 5.4 Ensure privileged containers are not used
- 5.6 Ensure SSH is not run within containers
- 5.7 Ensure privileged ports are not mapped within containers
- 5.10 Ensure the memory usage for container is limited
- 5.11 Ensure CPU priority is set appropriately
- 5.12 Ensure the container's root filesystem is mounted read-only
- 5.28 Ensure PIDs cgroup limit is used

**Docker Images:**
- 4.1 Ensure a user for the container has been created
- 4.2 Ensure that containers use only trusted base images
- 4.5 Ensure Content trust for Docker is enabled
- 4.6 Ensure that HEALTHCHECK instructions have been added to the container image
- 4.7 Ensure update instructions are not used alone in Dockerfiles

---

## Instructor Mentoring Guidance

**Week 11 is hands-on and tangible.** Students love seeing real CVEs in images they've pulled. Let them run Trivy against a popular image (nginx:1.20, node:14) and watch hundreds of CVEs appear — it makes the abstract concrete.

**Key coaching points:**
- Emphasize that CVE count ≠ exploitability. Help students understand CVSS v3 scores, attack vectors, and exploitability ratings.
- Falco rules can be tricky — the condition language uses Sysdig filter syntax. Pair on the first rule.
- The Docker socket mount is the most dangerous misconfiguration and most frequently seen in the wild.

**Mentoring session agenda (60 min):**
1. (10 min) Demo: `docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu bash` → `docker run --privileged ubuntu` from inside the container → host escape
2. (20 min) Code review of their hardened Dockerfile and CI gate
3. (20 min) Falco rules review — test each rule fires correctly
4. (10 min) Mock interview: "What is the difference between a container escape and a privilege escalation?"

---

## Hands-on Lab

### Lab 1: Image Scanning with Trivy

```bash
# Install Trivy
brew install trivy  # macOS
# or: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan a popular image for CVEs
trivy image --severity CRITICAL,HIGH nginx:1.20

# Scan with SARIF output (for GitHub Advanced Security)
trivy image \
  --format sarif \
  --output trivy-results.sarif \
  nginx:1.20

# Scan a Dockerfile for misconfigurations
trivy config Dockerfile

# Scan a local directory for secrets
trivy fs --security-checks secret .

# Generate a full HTML report
trivy image \
  --format template \
  --template "@contrib/html.tpl" \
  --output report.html \
  nginx:latest
```

### Lab 2: Hardened Dockerfile

```dockerfile
# Hardened Dockerfile following CIS Docker Benchmark
# Base image pinned to digest — not mutable tag
FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d

# Metadata
LABEL maintainer="security@company.com"
LABEL org.opencontainers.image.source="https://github.com/company/app"

# Install dependencies as root (needed for system packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.88.1-10+deb12u5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --shell /bin/bash --create-home appuser

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Copy application code
COPY --chown=appuser:appgroup src/ ./src/

# Switch to non-root user
USER appuser

# Read-only filesystem (runtime flag, but document it)
# docker run --read-only --tmpfs /tmp myapp

# Drop all capabilities (runtime flag)
# docker run --cap-drop ALL --cap-add NET_BIND_SERVICE myapp

# Resource limits (runtime or compose)
# docker run --memory 512m --cpus 1.0 myapp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose non-privileged port
EXPOSE 8080

ENTRYPOINT ["python", "-m", "src.app"]
```

### Lab 3: Falco Rules

```yaml
# rules/custom_container_rules.yaml

# Rule 1: Shell spawned inside container
- rule: Shell Spawned in Container
  desc: Detect a shell being spawned inside any container (potential breakout attempt)
  condition: >
    container.id != host
    and proc.name in (shell_binaries)
    and spawned_process
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name image=%container.image.repository
     shell=%proc.name pid=%proc.pid cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, T1059]

# Rule 2: Container reads sensitive file
- rule: Read Sensitive File in Container
  desc: Detect reads of sensitive host files from inside a container
  condition: >
    open_read
    and container
    and (fd.name in (sensitive_files) or fd.name startswith /etc/shadow)
    and not proc.name in (known_sensitive_file_readers)
  output: >
    Sensitive file read inside container
    (file=%fd.name user=%user.name container=%container.name
     image=%container.image.repository)
  priority: ERROR
  tags: [container, filesystem, T1003]

# Rule 3: Unexpected outbound connection
- rule: Unexpected Outbound Connection in Container
  desc: Container connects to an external IP (potential C2 or exfiltration)
  condition: >
    outbound
    and container
    and not proc.name in (known_network_tools)
    and not fd.sip in (rfc_1918_addresses)
    and fd.typechar = 4  # IPv4
  output: >
    Outbound connection from container
    (command=%proc.cmdline container=%container.name
     image=%container.image.repository dest_ip=%fd.sip dest_port=%fd.sport)
  priority: WARNING
  tags: [container, network, T1043]

# Rule 4: Container mounts Docker socket
- rule: Docker Socket Mounted in Container
  desc: Container has Docker socket mounted — container escape risk
  condition: >
    container
    and fd.name = /var/run/docker.sock
    and open_read
  output: >
    Docker socket accessed inside container
    (container=%container.name image=%container.image.repository
     user=%user.name)
  priority: CRITICAL
  tags: [container, escape, T1611]

# Rule 5: Write to sensitive directory
- rule: Write to Sensitive Directory in Container
  desc: File write to /etc, /bin, /sbin, /usr inside container
  condition: >
    container
    and open_write
    and (fd.name startswith /etc/ or fd.name startswith /bin/
         or fd.name startswith /sbin/ or fd.name startswith /usr/bin/)
    and not proc.name in (package_mgmt_binaries)
  output: >
    Write to sensitive directory in container
    (file=%fd.name user=%user.name container=%container.name
     image=%container.image.repository proc=%proc.cmdline)
  priority: WARNING
  tags: [container, filesystem, T1036]

# Rule 6: Privilege escalation via setuid
- rule: Setuid Binary Executed in Container
  desc: Setuid binary executed — potential privilege escalation
  condition: >
    container
    and spawned_process
    and proc.is_suid = true
    and not proc.name in (known_setuid_binaries)
  output: >
    Setuid binary executed in container
    (proc=%proc.name user=%user.name container=%container.name
     image=%container.image.repository)
  priority: ERROR
  tags: [container, privilege-escalation, T1548.001]

# Rule 7: Container tries to load kernel module
- rule: Kernel Module Load Attempt in Container
  desc: Attempt to load a kernel module from inside a container
  condition: >
    container
    and syscall.type in (init_module, finit_module)
  output: >
    Kernel module load attempt from container
    (proc=%proc.name user=%user.name container=%container.name
     image=%container.image.repository)
  priority: CRITICAL
  tags: [container, kernel, T1215]

# Rule 8: Crontab modification inside container
- rule: Crontab Modified in Container
  desc: Cron job added inside container — potential persistence
  condition: >
    container
    and open_write
    and (fd.name startswith /etc/cron or fd.name startswith /var/spool/cron)
  output: >
    Crontab modified inside container
    (file=%fd.name user=%user.name container=%container.name
     image=%container.image.repository)
  priority: WARNING
  tags: [container, persistence, T1053]
```

### Lab 4: GitHub Actions CI Security Gate

```yaml
# .github/workflows/security-scan.yml
name: Container Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write  # for SARIF upload

jobs:
  image-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan for CRITICAL CVEs
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL'
          exit-code: '1'  # FAIL the build on CRITICAL CVEs

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif

      - name: Scan Dockerfile configuration
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'

      - name: Check for non-root user
        run: |
          USER_INSTRUCTION=$(grep -i "^USER " Dockerfile || true)
          if [ -z "$USER_INSTRUCTION" ]; then
            echo "ERROR: Dockerfile does not set a non-root USER"
            exit 1
          fi
          echo "OK: USER instruction found: $USER_INSTRUCTION"

      - name: Check image is not running as root
        run: |
          USER_ID=$(docker inspect myapp:${{ github.sha }} \
            --format '{{.Config.User}}')
          if [ -z "$USER_ID" ] || [ "$USER_ID" = "root" ] || [ "$USER_ID" = "0" ]; then
            echo "ERROR: Container runs as root. Set USER in Dockerfile."
            exit 1
          fi
          echo "OK: Container runs as user: $USER_ID"
```

---

## Interview Skills Gained

**Q: What is a container escape and how do you prevent it?**
> A container escape is when an attacker inside a container gains access to the host OS or other containers. Common vectors: (1) privileged containers — full kernel access, (2) Docker socket mounted — can create privileged containers, (3) kernel CVEs — exploiting unpatched vulnerabilities. Prevention: never use `--privileged`, never mount the Docker socket, use read-only root filesystem, drop all capabilities and only add what's needed, keep the kernel patched.

**Q: What does `--read-only` do for a container?**
> It mounts the container's root filesystem as read-only, so any file write attempts fail with a permission error. Attackers who compromise a `--read-only` container cannot install tools, modify configuration, or create persistence mechanisms on disk. You typically need `--tmpfs /tmp` alongside it for the application's temporary file needs.

**Q: How do you handle CRITICAL CVEs in a base image you don't control?**
> (1) Rebuild with the latest patch version — check if the CVE is fixed upstream. (2) Use a minimal base image (distroless, scratch) that has fewer packages and thus fewer CVEs. (3) Accept the risk if the CVE is not exploitable in your context (e.g., requires local access, wrong architecture). (4) Apply vendor advisory workarounds. (5) If no fix exists, use WAF/network controls to reduce exploitability. Document the decision in your risk register.

---

## Submission Checklist

- [ ] Hardened Dockerfile committed — non-root user, no sensitive ENV vars, pinned base image
- [ ] `docker inspect` output showing user is not root (screenshot)
- [ ] Trivy scan result for base image committed to `reports/trivy-results.json`
- [ ] 8 custom Falco rules written and tested in `rules/custom_rules.yaml`
- [ ] Falco firing on shell-in-container test (screenshot or log output)
- [ ] GitHub Actions workflow blocking CRITICAL CVEs
- [ ] Before/after comparison: original vulnerable Dockerfile vs hardened version
- [ ] README explains each CIS control implemented and why

---

## Links

→ Full project: [projects/10-container-security-framework/](../../projects/10-container-security-framework/)
→ Next: [Week 12 — Kubernetes Security](../week-12/README.md)
