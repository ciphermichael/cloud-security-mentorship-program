# Project 10 — Container Security Framework: Step-by-Step Guide

> **Skill Level:** Intermediate | **Week:** 11

## Overview
Apply Docker CIS Benchmark hardening, scan images with Trivy, and write Falco runtime detection rules.

## Step 1 — Image Scanning with Trivy
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Scan an image
trivy image --severity CRITICAL,HIGH python:3.11

# Scan and output JSON
trivy image --format json --output reports/trivy-python.json python:3.11

# Fail build if CRITICAL CVEs found
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

## Step 2 — Hardened Dockerfile (CIS Docker Benchmark)
```dockerfile
# BEFORE (insecure)
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3
COPY . /app
CMD ["python3", "/app/main.py"]

# AFTER (CIS Benchmark Level 1 hardened)
# CIS 4.1 — Use trusted, minimal base image
FROM python:3.11-slim-bullseye

# CIS 4.6 — Add HEALTHCHECK instruction
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# CIS 4.9 — Use COPY instead of ADD
COPY requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt && \
    # Remove unnecessary packages
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY src/ /app/src/

# CIS 4.1 — Run as non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# CIS 4.5 — Do not use privileged ports
EXPOSE 8080

CMD ["python3", "-m", "src.app"]
```

## Step 3 — Docker CIS Benchmark Audit Script
```python
# src/docker_auditor.py
import subprocess, json

def check_images_no_latest_tag() -> list:
    """CIS 4.2 — Do not use latest tag"""
    result = subprocess.run(['docker','images','--format','{{.Repository}}:{{.Tag}}'],
                            capture_output=True, text=True)
    findings = []
    for img in result.stdout.strip().split('\n'):
        if img.endswith(':latest') or ':' not in img:
            findings.append({'severity':'MEDIUM','check':'LATEST_TAG',
                'detail':f'Image {img} uses :latest tag — use explicit version tags'})
    return findings

def check_containers_no_root() -> list:
    """CIS 5.4 — Container should not run as root"""
    result = subprocess.run(['docker','ps','--format','{{.ID}}'], capture_output=True, text=True)
    findings = []
    for cid in result.stdout.strip().split('\n'):
        if not cid: continue
        user_result = subprocess.run(['docker','exec', cid, 'id','-u'], capture_output=True, text=True)
        if user_result.returncode == 0 and user_result.stdout.strip() == '0':
            name_result = subprocess.run(['docker','inspect','--format','{{.Name}}',cid],
                                         capture_output=True, text=True)
            findings.append({'severity':'HIGH','check':'CONTAINER_RUNNING_AS_ROOT',
                'detail':f'Container {name_result.stdout.strip()} is running as root (UID 0)'})
    return findings

def check_no_privileged_containers() -> list:
    """CIS 5.4 — Do not use --privileged"""
    result = subprocess.run(['docker','ps','-q'], capture_output=True, text=True)
    findings = []
    for cid in result.stdout.strip().split('\n'):
        if not cid: continue
        inspect = subprocess.run(['docker','inspect',cid], capture_output=True, text=True)
        data = json.loads(inspect.stdout)[0]
        if data.get('HostConfig', {}).get('Privileged'):
            findings.append({'severity':'CRITICAL','check':'PRIVILEGED_CONTAINER',
                'detail':f'Container {cid[:12]} is running in privileged mode'})
    return findings

def run_audit() -> list:
    findings = []
    findings.extend(check_images_no_latest_tag())
    findings.extend(check_containers_no_root())
    findings.extend(check_no_privileged_containers())
    return findings
```

## Step 4 — Falco Runtime Detection Rules
```yaml
# falco_rules/custom_rules.yaml

# Rule 1: Shell spawned inside container
- rule: Shell Spawned in Container
  desc: Detect shell execution inside a running container
  condition: >
    container and proc.name in (bash, sh, zsh, dash, fish)
    and not proc.pname in (runc, containerd-shim, docker)
  output: >
    Shell spawned in container (user=%user.name cmd=%proc.cmdline 
    container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, T1059]

# Rule 2: Sensitive file read (/etc/shadow, /etc/passwd)
- rule: Read Sensitive File in Container
  desc: Attempt to read sensitive system files
  condition: >
    container and open_read and fd.name in (/etc/shadow, /etc/passwd, /etc/sudoers)
    and not proc.name in (sshd, login, su, sudo)
  output: >
    Sensitive file read in container (file=%fd.name 
    container=%container.name user=%user.name)
  priority: CRITICAL
  tags: [container, credentials, T1003]

# Rule 3: Outbound connection to non-approved destination
- rule: Unexpected Outbound Network in Container
  desc: Container making outbound connection to unexpected IP
  condition: >
    outbound and container
    and not fd.sip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    and not proc.name in (curl, wget, apt, pip, pip3)
  output: >
    Unexpected outbound connection (dest=%fd.rip:%fd.rport 
    container=%container.name proc=%proc.name)
  priority: WARNING
  tags: [container, network, T1071]

# Rule 4: Write to /tmp with executable bit
- rule: Write Executable to /tmp in Container
  desc: Writing an executable file to /tmp is suspicious
  condition: >
    container and open_write and fd.directory = /tmp
    and evt.arg.flags contains O_CREAT
  output: >
    Executable written to /tmp in container (file=%fd.name container=%container.name)
  priority: ERROR
  tags: [container, malware, T1059]

# Rule 5: cron modification
- rule: Cron Modification in Container
  desc: Modification of cron files for persistence
  condition: >
    container and open_write
    and fd.name startswith /etc/cron
  output: >
    Cron modification in container (file=%fd.name container=%container.name)
  priority: CRITICAL
  tags: [container, persistence, T1053]
```

## Step 5 — Deploy Falco + Run
```bash
# Install Falco
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
sudo apt-get install falco

# Run with custom rules
sudo falco -r falco_rules/custom_rules.yaml -o json_output=true

# Run inside Docker (for local testing)
docker run --rm -i -t --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v $(pwd)/falco_rules:/etc/falco/rules.d \
  falcosecurity/falco
```

## Step 6 — CI Pipeline Integration
```yaml
# .github/workflows/container-security.yml
name: Container Security Scan
on: [push]
jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
```
