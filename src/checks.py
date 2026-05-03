"""
Docker security check definitions.

Each check returns a list of Issue objects found in the audited artifact.
No Docker daemon connection required — all checks operate on parsed data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Status(str, Enum):
    FAIL = "FAIL"
    WARN = "WARN"
    PASS = "PASS"
    INFO = "INFO"


@dataclass
class Issue:
    check_id:    str
    title:       str
    severity:    Severity
    status:      Status
    description: str
    evidence:    str = ""
    remediation: str = ""
    source:      str = ""   # "dockerfile" | "compose" | "daemon" | "container"

    def to_dict(self) -> dict:
        return {
            "check_id":    self.check_id,
            "title":       self.title,
            "severity":    self.severity.value,
            "status":      self.status.value,
            "description": self.description,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "source":      self.source,
        }


# ---------------------------------------------------------------------------
# Dockerfile checks
# ---------------------------------------------------------------------------

_SENSITIVE_ENV_RE = re.compile(
    r"(?i)(password|secret|token|key|api_key|private|credential|passwd)\s*=\s*\S+",
)
_LATEST_TAG_RE = re.compile(r"^FROM\s+\S+:latest\b", re.IGNORECASE | re.MULTILINE)
_NO_TAG_RE     = re.compile(r"^FROM\s+([a-z0-9/_.-]+)\s*$", re.IGNORECASE | re.MULTILINE)
_ADD_RE        = re.compile(r"^ADD\s+", re.IGNORECASE | re.MULTILINE)
_CURL_PIPE_RE  = re.compile(r"curl\s+.*\|\s*(bash|sh)", re.IGNORECASE)
_CHMOD777_RE   = re.compile(r"chmod\s+(777|a\+rwx|o\+w)", re.IGNORECASE)
_ROOT_USER_RE  = re.compile(r"^USER\s+root\b", re.IGNORECASE | re.MULTILINE)
_NO_USER_RE    = re.compile(r"^USER\s+", re.IGNORECASE | re.MULTILINE)
_APT_CACHE_RE  = re.compile(
    r"apt-get\s+install(?!.*&&.*rm\s+-rf\s+/var/lib/apt)", re.IGNORECASE | re.DOTALL
)
_SUDO_RE       = re.compile(r"\bsudo\b")


def audit_dockerfile(content: str) -> list[Issue]:
    issues: list[Issue] = []
    src = "dockerfile"

    # DF01 — :latest tag
    if _LATEST_TAG_RE.search(content):
        issues.append(Issue(
            "DF01", "Image pinned to :latest",
            Severity.MEDIUM, Status.WARN,
            "Using :latest makes builds non-reproducible and may pull vulnerable images.",
            evidence=":latest tag detected in FROM instruction",
            remediation="Pin to a specific digest: FROM ubuntu:22.04@sha256:<digest>",
            source=src,
        ))

    # DF02 — untagged FROM
    for m in _NO_TAG_RE.finditer(content):
        img = m.group(1)
        if "scratch" not in img.lower():
            issues.append(Issue(
                "DF02", "Untagged base image",
                Severity.MEDIUM, Status.WARN,
                "FROM without a tag defaults to :latest.",
                evidence=f"FROM {img}",
                remediation=f"Add an explicit version tag: FROM {img}:<version>",
                source=src,
            ))

    # DF03 — sensitive ENV values
    for m in _SENSITIVE_ENV_RE.finditer(content):
        issues.append(Issue(
            "DF03", "Hardcoded secret in ENV",
            Severity.CRITICAL, Status.FAIL,
            "Secrets in ENV are visible via 'docker inspect' and stored in image layers.",
            evidence=m.group(0)[:80],
            remediation="Use --build-arg with secrets or Docker secrets / runtime env injection.",
            source=src,
        ))

    # DF04 — ADD instead of COPY
    if _ADD_RE.search(content):
        issues.append(Issue(
            "DF04", "ADD used instead of COPY",
            Severity.LOW, Status.WARN,
            "ADD has implicit URL fetching and tar extraction; COPY is safer and explicit.",
            remediation="Replace ADD with COPY for local files.",
            source=src,
        ))

    # DF05 — curl | bash
    if _CURL_PIPE_RE.search(content):
        issues.append(Issue(
            "DF05", "Piping curl output to shell",
            Severity.HIGH, Status.FAIL,
            "curl | bash is a supply chain attack vector — no integrity check on downloaded scripts.",
            evidence="curl ... | bash/sh detected",
            remediation="Download, verify checksum/signature, then execute separately.",
            source=src,
        ))

    # DF06 — chmod 777
    if _CHMOD777_RE.search(content):
        issues.append(Issue(
            "DF06", "World-writable permissions (chmod 777)",
            Severity.HIGH, Status.FAIL,
            "chmod 777 grants any user full read/write/execute access.",
            remediation="Use the minimum required permissions (e.g., chmod 755 or 644).",
            source=src,
        ))

    # DF07 — USER root
    if _ROOT_USER_RE.search(content):
        issues.append(Issue(
            "DF07", "Explicit USER root",
            Severity.HIGH, Status.FAIL,
            "Running the container process as root increases blast radius of any exploit.",
            remediation="Create a non-root user and switch: RUN useradd -m app && USER app",
            source=src,
        ))

    # DF08 — no USER instruction at all
    elif not _NO_USER_RE.search(content):
        issues.append(Issue(
            "DF08", "No USER instruction — defaults to root",
            Severity.HIGH, Status.FAIL,
            "Without a USER directive the container runs as root by default.",
            remediation="Add: RUN useradd -m app && USER app",
            source=src,
        ))

    # DF09 — apt-get without cache cleanup
    if _APT_CACHE_RE.search(content):
        issues.append(Issue(
            "DF09", "apt-get install without cache cleanup",
            Severity.LOW, Status.WARN,
            "Leaving apt cache in the image inflates image size.",
            remediation="Add: && rm -rf /var/lib/apt/lists/* to the same RUN layer.",
            source=src,
        ))

    # DF10 — sudo in RUN
    if _SUDO_RE.search(content):
        issues.append(Issue(
            "DF10", "sudo used inside RUN",
            Severity.LOW, Status.WARN,
            "sudo inside a Dockerfile is a code smell — build steps run as the USER already.",
            remediation="Remove sudo; set the correct USER before running privileged commands.",
            source=src,
        ))

    return issues


# ---------------------------------------------------------------------------
# docker-compose checks
# ---------------------------------------------------------------------------

def audit_compose(config: dict) -> list[Issue]:
    """
    Audit a parsed docker-compose config dict (from yaml.safe_load).
    Works with both v2 and v3 compose formats.
    """
    issues: list[Issue] = []
    src = "compose"
    services: dict[str, Any] = config.get("services") or {}

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        # DC01 — privileged
        if svc.get("privileged") is True:
            issues.append(Issue(
                "DC01", f"Privileged container: {name}",
                Severity.CRITICAL, Status.FAIL,
                "Privileged containers have full access to the host kernel — equivalent to root on the host.",
                evidence=f"services.{name}.privileged: true",
                remediation="Remove privileged: true. Grant only specific capabilities with cap_add.",
                source=src,
            ))

        # DC02 — host network
        net = svc.get("network_mode") or ""
        networks = svc.get("networks") or {}
        if net == "host" or (isinstance(networks, dict) and "host" in networks):
            issues.append(Issue(
                "DC02", f"Host network mode: {name}",
                Severity.HIGH, Status.FAIL,
                "Host networking exposes all host ports to the container, bypassing network isolation.",
                evidence=f"services.{name}.network_mode: host",
                remediation="Use a dedicated bridge network instead.",
                source=src,
            ))

        # DC03 — host PID namespace
        if svc.get("pid") == "host":
            issues.append(Issue(
                "DC03", f"Host PID namespace: {name}",
                Severity.HIGH, Status.FAIL,
                "Sharing the host PID namespace lets the container see and signal host processes.",
                evidence=f"services.{name}.pid: host",
                remediation="Remove pid: host.",
                source=src,
            ))

        # DC04 — host IPC namespace
        if svc.get("ipc") == "host":
            issues.append(Issue(
                "DC04", f"Host IPC namespace: {name}",
                Severity.MEDIUM, Status.WARN,
                "Sharing host IPC namespace allows access to shared memory of host processes.",
                evidence=f"services.{name}.ipc: host",
                remediation="Remove ipc: host.",
                source=src,
            ))

        # DC05 — sensitive environment variables
        env = svc.get("environment") or []
        env_pairs: list[str] = []
        if isinstance(env, dict):
            env_pairs = [f"{k}={v}" for k, v in env.items()]
        elif isinstance(env, list):
            env_pairs = [str(e) for e in env]
        for pair in env_pairs:
            if _SENSITIVE_ENV_RE.search(pair):
                issues.append(Issue(
                    "DC05", f"Hardcoded secret in environment: {name}",
                    Severity.CRITICAL, Status.FAIL,
                    "Secrets in compose environment blocks are stored in plain text.",
                    evidence=pair[:80],
                    remediation="Use Docker secrets or an .env file excluded from version control.",
                    source=src,
                ))
                break

        # DC06 — root volume mounts
        vols = svc.get("volumes") or []
        for vol in vols:
            raw = vol if isinstance(vol, str) else str(vol.get("source", ""))
            # "host_path:container_path" — take host part
            vol_str = raw.split(":")[0] if ":" in raw else raw
            if vol_str.startswith("/") and (
                vol_str in ("/", "/etc", "/var/run/docker.sock", "/proc", "/sys", "/dev")
            ):
                issues.append(Issue(
                    "DC06", f"Dangerous volume mount: {name}",
                    Severity.CRITICAL, Status.FAIL,
                    f"Mounting '{vol_str}' gives the container access to sensitive host resources.",
                    evidence=f"Volume: {vol_str}",
                    remediation="Avoid mounting host root, /etc, /proc, /sys, or the Docker socket.",
                    source=src,
                ))

        # DC07 — no resource limits
        deploy = svc.get("deploy") or {}
        resources = deploy.get("resources") or {}
        limits = resources.get("limits") or {}
        mem = limits.get("memory") or svc.get("mem_limit")
        cpu = limits.get("cpus") or svc.get("cpu_quota")
        if not mem and not cpu:
            issues.append(Issue(
                "DC07", f"No resource limits: {name}",
                Severity.LOW, Status.WARN,
                "Containers without resource limits can exhaust host memory/CPU (DoS).",
                remediation="Add deploy.resources.limits.memory and .cpus in the compose file.",
                source=src,
            ))

        # DC08 — no read-only root filesystem
        if not svc.get("read_only"):
            issues.append(Issue(
                "DC08", f"Writable root filesystem: {name}",
                Severity.LOW, Status.INFO,
                "A writable root filesystem lets attackers persist changes inside the container.",
                remediation="Add read_only: true and mount tmpfs for writable paths.",
                source=src,
            ))

    return issues


# ---------------------------------------------------------------------------
# Docker daemon config checks
# ---------------------------------------------------------------------------

def audit_daemon(config: dict) -> list[Issue]:
    """Audit a parsed /etc/docker/daemon.json config dict."""
    issues: list[Issue] = []
    src = "daemon"

    # DD01 — no-new-privileges not set
    if not config.get("no-new-privileges"):
        issues.append(Issue(
            "DD01", "no-new-privileges not enabled",
            Severity.MEDIUM, Status.WARN,
            "Without no-new-privileges, processes inside containers can gain additional privileges via SUID/SGID.",
            remediation='Add "no-new-privileges": true to daemon.json.',
            source=src,
        ))

    # DD02 — userland-proxy not disabled
    if config.get("userland-proxy", True):
        issues.append(Issue(
            "DD02", "Userland proxy not disabled",
            Severity.LOW, Status.WARN,
            "The userland proxy adds an extra process per published port; disabling it improves performance and reduces attack surface.",
            remediation='Add "userland-proxy": false to daemon.json.',
            source=src,
        ))

    # DD03 — live-restore not enabled
    if not config.get("live-restore"):
        issues.append(Issue(
            "DD03", "live-restore not enabled",
            Severity.LOW, Status.INFO,
            "live-restore keeps containers running during Docker daemon restarts.",
            remediation='Add "live-restore": true to daemon.json.',
            source=src,
        ))

    # DD04 — log driver
    log_driver = config.get("log-driver", "json-file")
    if log_driver == "none":
        issues.append(Issue(
            "DD04", "Logging disabled (log-driver: none)",
            Severity.HIGH, Status.FAIL,
            "Disabling logs prevents security monitoring and incident response.",
            remediation='Set "log-driver" to "json-file" or a centralized logging driver.',
            source=src,
        ))

    # DD05 — icc (inter-container communication)
    if config.get("icc", True):
        issues.append(Issue(
            "DD05", "Inter-container communication (ICC) enabled",
            Severity.MEDIUM, Status.WARN,
            "ICC allows all containers on the default bridge to communicate without explicit links.",
            remediation='Add "icc": false to daemon.json and use explicit network links.',
            source=src,
        ))

    # DD06 — experimental features
    if config.get("experimental"):
        issues.append(Issue(
            "DD06", "Experimental features enabled",
            Severity.LOW, Status.WARN,
            "Experimental features may have unstable security properties.",
            remediation='Remove "experimental": true in production.',
            source=src,
        ))

    return issues
