# Docker Security Audit

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-51%20passing-brightgreen)

Static security auditor for Dockerfiles, docker-compose files, and Docker daemon configuration. Detects misconfigurations, hardcoded secrets, dangerous mounts, missing resource limits, and CIS Benchmark violations.

---

## Checks

### Dockerfile (10 checks)

| ID   | Check | Severity |
|------|-------|----------|
| DF01 | Image pinned to `:latest` | MEDIUM |
| DF02 | Untagged base image | MEDIUM |
| DF03 | Hardcoded secret in `ENV` | CRITICAL |
| DF04 | `ADD` instead of `COPY` | LOW |
| DF05 | `curl \| bash` — no integrity check | HIGH |
| DF06 | `chmod 777` — world-writable permissions | HIGH |
| DF07 | `USER root` explicit | HIGH |
| DF08 | No `USER` directive — defaults to root | HIGH |
| DF09 | `apt-get install` without cache cleanup | LOW |
| DF10 | `sudo` used inside `RUN` | LOW |

### docker-compose (8 checks)

| ID   | Check | Severity |
|------|-------|----------|
| DC01 | `privileged: true` — full host kernel access | CRITICAL |
| DC02 | `network_mode: host` — bypass network isolation | HIGH |
| DC03 | `pid: host` — see host processes | HIGH |
| DC04 | `ipc: host` — shared host memory | MEDIUM |
| DC05 | Hardcoded secret in `environment` | CRITICAL |
| DC06 | Dangerous volume mount (`/`, `/etc`, Docker socket) | CRITICAL |
| DC07 | No resource limits — potential DoS | LOW |
| DC08 | Writable root filesystem | LOW |

### Daemon config (6 checks)

| ID   | Check | Severity |
|------|-------|----------|
| DD01 | `no-new-privileges` not enabled | MEDIUM |
| DD02 | Userland proxy not disabled | LOW |
| DD03 | `live-restore` not enabled | LOW |
| DD04 | Logging disabled (`log-driver: none`) | HIGH |
| DD05 | Inter-container communication (ICC) enabled | MEDIUM |
| DD06 | Experimental features enabled in production | LOW |

---

## Usage

```bash
pip install -r requirements.txt

# Audit a Dockerfile
python -m src dockerfile ./Dockerfile

# Audit a docker-compose file
python -m src compose ./docker-compose.yml

# Audit Docker daemon config
python -m src daemon --path /etc/docker/daemon.json

# JSON output
python -m src dockerfile ./Dockerfile --format json

# CI/CD — exits 1 on CRITICAL/HIGH failures
python -m src compose ./docker-compose.prod.yml || exit 1
```

---

## Example Output

```
Docker Security Audit
  Target  : ./Dockerfile
  Score   : 52/100
  Issues  : FAIL 3  WARN 2  PASS 0

[DF03] [FAIL] [CRITICAL] Hardcoded secret in ENV
       Secrets in ENV are visible via 'docker inspect'.
       Evidence : DB_PASSWORD=supersecret
       Fix      : Use Docker secrets or runtime env injection.

[DF08] [FAIL] [HIGH] No USER instruction — defaults to root
       Fix      : Add: RUN useradd -m app && USER app
```

---

## Project Structure

```
src/
├── checks.py    ← 24 check functions (dockerfile, compose, daemon)
├── report.py    ← AuditReport + console/JSON renderer
├── __main__.py  ← CLI (dockerfile / compose / daemon subcommands)
└── __init__.py
tests/
└── test_docker_audit.py  ← 51 tests
```

---

## References

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

---

## License

MIT
