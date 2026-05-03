"""Report renderer — console and JSON."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .checks import Issue, Severity, Status

_R   = "\033[0m"
_B   = "\033[1m"
_RED = "\033[91m"
_YEL = "\033[93m"
_CYN = "\033[96m"
_GRN = "\033[92m"
_DIM = "\033[2m"

_SEV_COLOR = {
    Severity.CRITICAL: _RED,
    Severity.HIGH:     _RED,
    Severity.MEDIUM:   _YEL,
    Severity.LOW:      _CYN,
    Severity.INFO:     _GRN,
}
_STATUS_COLOR = {
    Status.FAIL: _RED,
    Status.WARN: _YEL,
    Status.PASS: _GRN,
    Status.INFO: _CYN,
}


@dataclass
class AuditReport:
    target: str
    issues: list[Issue] = field(default_factory=list)
    audited_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def passes(self) -> list[Issue]:
        return [i for i in self.issues if i.status == Status.PASS]

    @property
    def failures(self) -> list[Issue]:
        return [i for i in self.issues if i.status == Status.FAIL]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.status == Status.WARN]

    def score(self) -> int:
        """0–100 compliance score: penalties for FAIL/WARN."""
        total = len(self.issues)
        if not total:
            return 100
        penalty = sum(
            4 if i.severity in (Severity.CRITICAL, Severity.HIGH) else
            2 if i.severity == Severity.MEDIUM else 1
            for i in self.issues
            if i.status in (Status.FAIL, Status.WARN)
        )
        return max(0, 100 - penalty)

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "audited_at": self.audited_at.isoformat(),
            "score":      self.score(),
            "summary": {
                "total":    len(self.issues),
                "fail":     len(self.failures),
                "warn":     len(self.warnings),
                "pass":     len(self.passes),
                "critical": sum(1 for i in self.issues if i.severity == Severity.CRITICAL),
                "high":     sum(1 for i in self.issues if i.severity == Severity.HIGH),
                "medium":   sum(1 for i in self.issues if i.severity == Severity.MEDIUM),
                "low":      sum(1 for i in self.issues if i.severity == Severity.LOW),
            },
            "issues": [i.to_dict() for i in self.issues],
        }


def render_console(report: AuditReport, color: bool = True) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_R}" if color else text

    buf = io.StringIO()
    w = buf.write

    w(c(_B, "═" * 60) + "\n")
    w(c(_B, "  Docker Security Audit") + "\n")
    w(c(_B, "═" * 60) + "\n")
    w(f"  Target    : {report.target}\n")
    w(f"  Audited   : {report.audited_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    d = report.to_dict()
    score_color = _GRN if report.score() >= 80 else (_YEL if report.score() >= 50 else _RED)
    w(f"  Score     : {c(score_color, str(report.score()))}/100\n")
    w(f"  Issues    : {c(_RED,'FAIL')} {d['summary']['fail']}  "
      f"{c(_YEL,'WARN')} {d['summary']['warn']}  "
      f"{c(_GRN,'PASS')} {d['summary']['pass']}\n\n")

    if not report.issues:
        w(c(_GRN, "  No issues detected.\n"))
        return buf.getvalue()

    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                  Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    for issue in sorted(report.issues, key=lambda x: _sev_order[x.severity]):
        if issue.status == Status.PASS:
            continue
        sc = _STATUS_COLOR[issue.status]
        ev = _SEV_COLOR[issue.severity]
        w(c(_B, f"  [{issue.check_id}] ") +
          c(sc, f"[{issue.status.value}] ") +
          c(ev, f"[{issue.severity.value}]") +
          f" {issue.title}\n")
        w(f"         {issue.description}\n")
        if issue.evidence:
            w(c(_DIM, f"         Evidence : {issue.evidence}\n"))
        if issue.remediation:
            w(c(_GRN, f"         Fix      : {issue.remediation}\n"))
        w("\n")

    w(c(_B, "═" * 60) + "\n")
    return buf.getvalue()


def render_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"
