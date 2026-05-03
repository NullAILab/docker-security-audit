"""Tests for Docker security audit checks."""

from __future__ import annotations

import json

import pytest

from src.checks import (
    Issue, Severity, Status,
    audit_compose, audit_daemon, audit_dockerfile,
)
from src.report import AuditReport, render_console, render_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ids(issues: list[Issue]) -> set[str]:
    return {i.check_id for i in issues}


# ---------------------------------------------------------------------------
# Dockerfile — DF01 :latest tag
# ---------------------------------------------------------------------------

class TestDF01Latest:
    def test_latest_detected(self):
        df = "FROM ubuntu:latest\nRUN echo hi\nUSER app"
        assert "DF01" in ids(audit_dockerfile(df))

    def test_pinned_version_ok(self):
        df = "FROM ubuntu:22.04\nUSER app"
        assert "DF01" not in ids(audit_dockerfile(df))

    def test_latest_in_multistage_detected(self):
        df = "FROM node:latest AS build\nFROM nginx:latest\nUSER nginx"
        result = audit_dockerfile(df)
        assert "DF01" in ids(result)


# ---------------------------------------------------------------------------
# Dockerfile — DF02 untagged
# ---------------------------------------------------------------------------

class TestDF02Untagged:
    def test_untagged_detected(self):
        df = "FROM ubuntu\nUSER app"
        assert "DF02" in ids(audit_dockerfile(df))

    def test_tagged_ok(self):
        df = "FROM ubuntu:22.04\nUSER app"
        assert "DF02" not in ids(audit_dockerfile(df))

    def test_scratch_ok(self):
        df = "FROM scratch\nCOPY binary /\nENTRYPOINT [\"/binary\"]"
        assert "DF02" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Dockerfile — DF03 hardcoded secret
# ---------------------------------------------------------------------------

class TestDF03Secret:
    def test_password_detected(self):
        df = "FROM ubuntu:22.04\nENV DB_PASSWORD=supersecret\nUSER app"
        issues = audit_dockerfile(df)
        assert "DF03" in ids(issues)
        f = next(i for i in issues if i.check_id == "DF03")
        assert f.severity == Severity.CRITICAL

    def test_token_detected(self):
        df = "FROM ubuntu:22.04\nENV API_TOKEN=abcdef123\nUSER app"
        assert "DF03" in ids(audit_dockerfile(df))

    def test_clean_env_ok(self):
        df = "FROM ubuntu:22.04\nENV APP_PORT=8080\nUSER app"
        assert "DF03" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Dockerfile — DF04 ADD
# ---------------------------------------------------------------------------

class TestDF04Add:
    def test_add_detected(self):
        df = "FROM ubuntu:22.04\nADD . /app\nUSER app"
        assert "DF04" in ids(audit_dockerfile(df))

    def test_copy_ok(self):
        df = "FROM ubuntu:22.04\nCOPY . /app\nUSER app"
        assert "DF04" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Dockerfile — DF05 curl | bash
# ---------------------------------------------------------------------------

class TestDF05CurlBash:
    def test_curl_pipe_bash_detected(self):
        df = "FROM ubuntu:22.04\nRUN curl https://install.sh | bash\nUSER app"
        assert "DF05" in ids(audit_dockerfile(df))

    def test_curl_pipe_sh_detected(self):
        df = "FROM ubuntu:22.04\nRUN curl https://x.sh | sh\nUSER app"
        assert "DF05" in ids(audit_dockerfile(df))

    def test_plain_curl_ok(self):
        df = "FROM ubuntu:22.04\nRUN curl -o file.txt https://example.com/file\nUSER app"
        assert "DF05" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Dockerfile — DF06 chmod 777
# ---------------------------------------------------------------------------

class TestDF06Chmod777:
    def test_chmod_777_detected(self):
        df = "FROM ubuntu:22.04\nRUN chmod 777 /app\nUSER app"
        assert "DF06" in ids(audit_dockerfile(df))

    def test_chmod_755_ok(self):
        df = "FROM ubuntu:22.04\nRUN chmod 755 /app\nUSER app"
        assert "DF06" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Dockerfile — DF07/DF08 USER root / no USER
# ---------------------------------------------------------------------------

class TestDF07DF08User:
    def test_user_root_detected(self):
        df = "FROM ubuntu:22.04\nUSER root"
        assert "DF07" in ids(audit_dockerfile(df))

    def test_no_user_detected(self):
        df = "FROM ubuntu:22.04\nRUN echo hi"
        assert "DF08" in ids(audit_dockerfile(df))

    def test_non_root_user_ok(self):
        df = "FROM ubuntu:22.04\nRUN useradd -m app\nUSER app"
        result = ids(audit_dockerfile(df))
        assert "DF07" not in result
        assert "DF08" not in result


# ---------------------------------------------------------------------------
# Dockerfile — DF09 apt-get cache
# ---------------------------------------------------------------------------

class TestDF09AptCache:
    def test_no_cleanup_detected(self):
        df = "FROM ubuntu:22.04\nRUN apt-get install -y curl\nUSER app"
        assert "DF09" in ids(audit_dockerfile(df))

    def test_with_cleanup_ok(self):
        df = "FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\nUSER app"
        assert "DF09" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Dockerfile — DF10 sudo
# ---------------------------------------------------------------------------

class TestDF10Sudo:
    def test_sudo_detected(self):
        df = "FROM ubuntu:22.04\nRUN sudo apt-get install curl\nUSER app"
        assert "DF10" in ids(audit_dockerfile(df))

    def test_no_sudo_ok(self):
        df = "FROM ubuntu:22.04\nRUN apt-get install curl\nUSER app"
        assert "DF10" not in ids(audit_dockerfile(df))


# ---------------------------------------------------------------------------
# Compose — DC01 privileged
# ---------------------------------------------------------------------------

class TestDC01Privileged:
    def test_privileged_detected(self):
        cfg = {"services": {"web": {"image": "nginx", "privileged": True}}}
        assert "DC01" in ids(audit_compose(cfg))

    def test_not_privileged_ok(self):
        cfg = {"services": {"web": {"image": "nginx"}}}
        assert "DC01" not in ids(audit_compose(cfg))


# ---------------------------------------------------------------------------
# Compose — DC02 host network
# ---------------------------------------------------------------------------

class TestDC02HostNetwork:
    def test_host_network_mode(self):
        cfg = {"services": {"web": {"image": "nginx", "network_mode": "host"}}}
        assert "DC02" in ids(audit_compose(cfg))

    def test_bridge_ok(self):
        cfg = {"services": {"web": {"image": "nginx", "network_mode": "bridge"}}}
        assert "DC02" not in ids(audit_compose(cfg))


# ---------------------------------------------------------------------------
# Compose — DC03 host PID
# ---------------------------------------------------------------------------

class TestDC03HostPID:
    def test_host_pid(self):
        cfg = {"services": {"web": {"image": "nginx", "pid": "host"}}}
        assert "DC03" in ids(audit_compose(cfg))


# ---------------------------------------------------------------------------
# Compose — DC05 secrets in env
# ---------------------------------------------------------------------------

class TestDC05EnvSecrets:
    def test_dict_env_secret(self):
        cfg = {"services": {"db": {"image": "postgres", "environment": {"DB_PASSWORD": "secret123"}}}}
        assert "DC05" in ids(audit_compose(cfg))

    def test_list_env_secret(self):
        cfg = {"services": {"db": {"image": "postgres", "environment": ["DB_PASSWORD=secret123"]}}}
        assert "DC05" in ids(audit_compose(cfg))

    def test_clean_env_ok(self):
        cfg = {"services": {"web": {"image": "nginx", "environment": {"PORT": "8080"}}}}
        assert "DC05" not in ids(audit_compose(cfg))


# ---------------------------------------------------------------------------
# Compose — DC06 dangerous volumes
# ---------------------------------------------------------------------------

class TestDC06Volumes:
    def test_docker_socket_mount(self):
        cfg = {"services": {"web": {"image": "nginx", "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}}
        assert "DC06" in ids(audit_compose(cfg))

    def test_root_mount(self):
        cfg = {"services": {"web": {"image": "nginx", "volumes": ["/:/host"]}}}
        assert "DC06" in ids(audit_compose(cfg))

    def test_app_volume_ok(self):
        cfg = {"services": {"web": {"image": "nginx", "volumes": ["./app:/app"]}}}
        assert "DC06" not in ids(audit_compose(cfg))


# ---------------------------------------------------------------------------
# Compose — empty / edge cases
# ---------------------------------------------------------------------------

class TestComposeEdgeCases:
    def test_empty_services(self):
        assert audit_compose({}) == []
        assert audit_compose({"services": {}}) == []

    def test_multiple_services(self):
        cfg = {"services": {
            "web":  {"image": "nginx", "privileged": True},
            "db":   {"image": "postgres", "privileged": True},
        }}
        result = audit_compose(cfg)
        dc01 = [i for i in result if i.check_id == "DC01"]
        assert len(dc01) == 2


# ---------------------------------------------------------------------------
# Daemon checks
# ---------------------------------------------------------------------------

class TestDaemonChecks:
    def test_empty_config_flags_all(self):
        issues = audit_daemon({})
        check_ids = ids(issues)
        assert "DD01" in check_ids
        assert "DD02" in check_ids

    def test_no_new_privileges_ok(self):
        issues = audit_daemon({"no-new-privileges": True})
        assert "DD01" not in ids(issues)

    def test_logging_none_critical(self):
        issues = audit_daemon({"log-driver": "none"})
        dd04 = next((i for i in issues if i.check_id == "DD04"), None)
        assert dd04 is not None
        assert dd04.severity == Severity.HIGH

    def test_experimental_flagged(self):
        issues = audit_daemon({"experimental": True})
        assert "DD06" in ids(issues)

    def test_secure_config(self):
        config = {
            "no-new-privileges": True,
            "userland-proxy": False,
            "live-restore": True,
            "log-driver": "json-file",
            "icc": False,
        }
        issues = audit_daemon(config)
        flagged = [i for i in issues if i.status == Status.FAIL or i.status == Status.WARN]
        assert len(flagged) == 0


# ---------------------------------------------------------------------------
# AuditReport
# ---------------------------------------------------------------------------

class TestAuditReport:
    def _report(self) -> AuditReport:
        df = "FROM ubuntu:latest\nENV PASSWORD=secret\nRUN chmod 777 /app"
        issues = audit_dockerfile(df)
        return AuditReport(target="Dockerfile", issues=issues)

    def test_score_below_100_with_issues(self):
        r = self._report()
        assert r.score() < 100

    def test_score_100_no_issues(self):
        r = AuditReport(target="clean")
        assert r.score() == 100

    def test_to_dict_structure(self):
        r = self._report()
        d = r.to_dict()
        assert "score" in d
        assert "summary" in d
        assert "issues" in d
        assert d["target"] == "Dockerfile"

    def test_failures_property(self):
        r = self._report()
        for f in r.failures:
            assert f.status == Status.FAIL

    def test_warnings_property(self):
        r = self._report()
        for w in r.warnings:
            assert w.status == Status.WARN


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

class TestRendering:
    def _report(self) -> AuditReport:
        issues = audit_dockerfile(
            "FROM ubuntu:latest\nENV SECRET=abc\nRUN chmod 777 /\nRUN apt-get install curl"
        )
        return AuditReport(target="Dockerfile", issues=issues)

    def test_console_no_color(self):
        r = self._report()
        out = render_console(r, color=False)
        assert "\033[" not in out
        assert "Docker Security Audit" in out

    def test_console_with_color(self):
        out = render_console(self._report(), color=True)
        assert "\033[" in out

    def test_json_valid(self):
        out = render_json(self._report())
        data = json.loads(out)
        assert "score" in data
        assert isinstance(data["issues"], list)

    def test_empty_report_console(self):
        r = AuditReport(target="empty")
        out = render_console(r, color=False)
        assert "No issues" in out

    def test_issue_to_dict(self):
        i = Issue("DF03", "Secret", Severity.CRITICAL, Status.FAIL,
                  "desc", "evidence", "fix", "dockerfile")
        d = i.to_dict()
        assert d["check_id"] == "DF03"
        assert d["severity"] == "CRITICAL"
        assert d["source"] == "dockerfile"
