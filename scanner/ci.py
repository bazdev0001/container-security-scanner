"""
CI-native output adapters.

Emits findings in the format each CI platform natively understands:
  - GitHub Actions: workflow commands (::error, ::warning)
  - Jenkins: Warnings Next Generation plugin JSON
  - GitLab: GitLab SAST report format
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.main import Finding

SUPPORTED_ADAPTERS = ("github", "jenkins", "gitlab")


class CIAdapter:
    """
    Factory / dispatcher for CI-specific output.

    Usage:
        adapter = CIAdapter("github")
        adapter.emit(findings)
    """

    def __init__(self, mode: str) -> None:
        mode = mode.lower().strip()
        if mode not in SUPPORTED_ADAPTERS:
            raise ValueError(
                f"Unknown CI mode: {mode!r}. "
                f"Supported: {', '.join(SUPPORTED_ADAPTERS)}"
            )
        self.mode = mode

    def emit(self, findings: list["Finding"]) -> None:
        if self.mode == "github":
            emit_github_annotations(findings)
        elif self.mode == "jenkins":
            emit_jenkins_warnings(findings)
        elif self.mode == "gitlab":
            emit_gitlab_sast(findings)


# ---------------------------------------------------------------------------
# GitHub Actions
# ---------------------------------------------------------------------------

_GHA_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "notice",
    "UNKNOWN": "notice",
}


def emit_github_annotations(findings: list["Finding"]) -> None:
    """
    Print GitHub Actions workflow commands.

    These appear as annotations on the PR diff and in the Actions log.
    See: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions
    """
    if not findings:
        print("::notice::Container scan passed — no findings above policy threshold.")
        return

    for finding in findings:
        level = _GHA_SEVERITY_TO_LEVEL.get(finding.severity.upper(), "warning")
        title = f"[{finding.severity}] {finding.vulnerability_id} in {finding.pkg_name}"
        fix_msg = (
            f"Upgrade to {finding.fixed_version}"
            if finding.fixed_version
            else "No fix available"
        )
        message = (
            f"{finding.title or finding.vulnerability_id} | "
            f"Installed: {finding.installed_version} | "
            f"{fix_msg}"
        )
        # Sanitise — GHA commands cannot contain % or newlines in message field
        message = message.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D")
        title = title.replace("%", "%25").replace("\n", "%0A")

        file_field = f",file={finding.target}" if finding.target else ""
        print(f"::{level} title={title}{file_field}::{message}")


# ---------------------------------------------------------------------------
# Jenkins Warnings Next Generation
# ---------------------------------------------------------------------------

def emit_jenkins_warnings(findings: list["Finding"]) -> None:
    """
    Print Jenkins Warnings Next Generation plugin JSON to stdout.

    Configure your Jenkinsfile:
        recordIssues(tools: [issues(pattern: 'scan-*.json', id: 'container-cve')])
    """
    _JENKINS_SEVERITY = {
        "CRITICAL": "HIGH",
        "HIGH": "HIGH",
        "MEDIUM": "NORMAL",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
    }

    issues = []
    for finding in findings:
        issues.append({
            "fileName": finding.target or "Dockerfile",
            "severity": _JENKINS_SEVERITY.get(finding.severity.upper(), "NORMAL"),
            "message": (
                f"[{finding.severity}] {finding.vulnerability_id}: "
                f"{finding.pkg_name} {finding.installed_version}"
                + (f" → fix: {finding.fixed_version}" if finding.fixed_version else "")
            ),
            "description": finding.description or finding.title or "",
            "origin": "container-security-scanner",
            "type": finding.vulnerability_id,
        })

    print(json.dumps({"issues": issues}, indent=2))


# ---------------------------------------------------------------------------
# GitLab SAST
# ---------------------------------------------------------------------------

def emit_gitlab_sast(findings: list["Finding"]) -> None:
    """
    Print a GitLab SAST report to stdout.

    In .gitlab-ci.yml:
        artifacts:
          reports:
            sast: gl-sast-report.json
    Redirect this output to gl-sast-report.json.

    Spec: https://docs.gitlab.com/ee/user/application_security/sast/#output-file
    """
    _GL_SEVERITY = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "UNKNOWN": "Unknown",
    }

    vulnerabilities = []
    for finding in findings:
        vuln_id = f"{finding.vulnerability_id}-{finding.pkg_name}".replace(" ", "-")
        cve_link = f"https://nvd.nist.gov/vuln/detail/{finding.vulnerability_id}"
        identifiers = [
            {
                "type": "cve",
                "name": finding.vulnerability_id,
                "value": finding.vulnerability_id,
                "url": cve_link,
            }
        ]
        if finding.references:
            for ref in finding.references[:3]:
                if "nvd.nist.gov" not in ref:
                    identifiers.append({
                        "type": "url",
                        "name": ref,
                        "value": ref,
                        "url": ref,
                    })

        solution = None
        if finding.fixed_version:
            solution = (
                f"Upgrade {finding.pkg_name} from {finding.installed_version} "
                f"to {finding.fixed_version}"
            )

        vulnerabilities.append({
            "id": vuln_id,
            "category": "container_scanning",
            "name": finding.title or finding.vulnerability_id,
            "message": (
                f"{finding.severity} vulnerability {finding.vulnerability_id} "
                f"in {finding.pkg_name} {finding.installed_version}"
            ),
            "description": finding.description or "",
            "severity": _GL_SEVERITY.get(finding.severity.upper(), "Unknown"),
            "solution": solution,
            "scanner": {
                "id": "container-security-scanner",
                "name": "Container Security Scanner",
            },
            "location": {
                "image": finding.target or "",
                "dependency": {
                    "package": {"name": finding.pkg_name},
                    "version": finding.installed_version,
                },
            },
            "identifiers": identifiers,
        })

    report = {
        "schema": "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json",
        "version": "15.0.4",
        "scan": {
            "scanner": {
                "id": "container-security-scanner",
                "name": "Container Security Scanner",
                "url": "https://github.com/barry-auyeung/container-security-scanner",
                "version": "1.0.0",
                "vendor": {"name": "Barry Au Yeung"},
            },
            "type": "container_scanning",
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    }
    print(json.dumps(report, indent=2))
