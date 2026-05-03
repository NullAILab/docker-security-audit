"""CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import audit_compose, audit_daemon, audit_dockerfile
from .report import AuditReport, render_console, render_json


def main() -> None:
    p = argparse.ArgumentParser(
        prog="docker-audit",
        description="Docker Security Audit — Dockerfile, Compose, and daemon config checks",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    df_p = sub.add_parser("dockerfile", help="Audit a Dockerfile")
    df_p.add_argument("path", help="Path to Dockerfile")
    df_p.add_argument("--format", choices=["console", "json"], default="console")
    df_p.add_argument("--no-color", action="store_true")

    co_p = sub.add_parser("compose", help="Audit a docker-compose.yml")
    co_p.add_argument("path", help="Path to docker-compose.yml")
    co_p.add_argument("--format", choices=["console", "json"], default="console")
    co_p.add_argument("--no-color", action="store_true")

    dm_p = sub.add_parser("daemon", help="Audit /etc/docker/daemon.json")
    dm_p.add_argument("--path", default="/etc/docker/daemon.json")
    dm_p.add_argument("--format", choices=["console", "json"], default="console")
    dm_p.add_argument("--no-color", action="store_true")

    args = p.parse_args()

    issues = []
    target = ""

    if args.cmd == "dockerfile":
        target = args.path
        content = Path(args.path).read_text(encoding="utf-8")
        issues = audit_dockerfile(content)

    elif args.cmd == "compose":
        target = args.path
        try:
            import yaml  # type: ignore
            config = yaml.safe_load(Path(args.path).read_text(encoding="utf-8"))
        except ImportError:
            print("error: PyYAML required — pip install pyyaml", file=sys.stderr)
            sys.exit(2)
        issues = audit_compose(config)

    elif args.cmd == "daemon":
        target = args.path
        try:
            config = json.loads(Path(args.path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            config = {}
        issues = audit_daemon(config)

    report = AuditReport(target=target, issues=issues)

    if args.format == "json":
        sys.stdout.write(render_json(report))
    else:
        sys.stdout.write(render_console(report, color=not args.no_color))

    failures = sum(1 for i in issues if i.status.value == "FAIL"
                   and i.severity.value in ("CRITICAL", "HIGH"))
    sys.exit(1 if failures > 0 else 0)


if __name__ == "__main__":
    main()
