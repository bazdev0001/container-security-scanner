"""
container-security-scanner — main CLI entry point.

Wraps Trivy with smarter policies, richer output, and CI-native blocking.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from scanner.policies import PolicyEngine, load_policy
from scanner.report import ReportGenerator
from scanner.ci import CIAdapter

app = typer.Typer(
    name="scanner",
    help="Docker image CVE scanner with policy-based CI blocking.",
    add_completion=False,
)
console = Console()

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
}


@dataclass
class Finding:
    """A single CVE finding from Trivy."""

    vulnerability_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    description: str
    references: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    target: str = ""

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_version and self.fixed_version != "")

    def to_dict(self) -> dict:
        return {
            "vulnerability_id": self.vulnerability_id,
            "pkg_name": self.pkg_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "target": self.target,
            "has_fix": self.has_fix,
        }


@dataclass
class ScanResult:
    """Aggregated result of scanning one image."""

    image: str
    scan_time: float
    findings: list[Finding]
    trivy_version: str = ""
    db_version: str = ""

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def counts(self) -> dict[str, int]:
        return {s: len(v) for s, v in self.by_severity.items()}


def run_trivy(
    image: str,
    trivy_bin: str = "trivy",
    timeout: int = 300,
    cache_dir: Optional[str] = None,
    tar_path: Optional[str] = None,
) -> dict:
    """Invoke Trivy and return parsed JSON output."""
    cmd = [
        trivy_bin,
        "image",
        "--format", "json",
        "--exit-code", "0",  # we handle exit logic ourselves
        "--quiet",
    ]
    if cache_dir:
        cmd += ["--cache-dir", cache_dir]
    if tar_path:
        cmd += ["--input", tar_path]
    cmd.append(image)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/bold red] Trivy binary not found at '{trivy_bin}'. "
            "Install Trivy: https://github.com/aquasecurity/trivy#installation"
        )
        raise typer.Exit(2)
    except subprocess.TimeoutExpired:
        console.print(
            f"[bold red]Error:[/bold red] Trivy scan timed out after {timeout}s."
        )
        raise typer.Exit(2)

    if result.returncode not in (0, 1):
        console.print(f"[bold red]Trivy error:[/bold red]\n{result.stderr}")
        raise typer.Exit(2)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        console.print(f"[bold red]Failed to parse Trivy output:[/bold red] {exc}")
        console.print(f"Raw output: {result.stdout[:500]}")
        raise typer.Exit(2)


def parse_trivy_json(raw: dict, image: str) -> list[Finding]:
    """Convert Trivy JSON output into a flat list of Finding objects."""
    findings: list[Finding] = []
    results = raw.get("Results", [])
    for result in results:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for source_data in cvss_data.values():
                score = source_data.get("V3Score") or source_data.get("V2Score")
                if score is not None:
                    cvss_score = float(score)
                    break

            findings.append(
                Finding(
                    vulnerability_id=vuln.get("VulnerabilityID", ""),
                    pkg_name=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    title=vuln.get("Title", ""),
                    description=vuln.get("Description", ""),
                    references=vuln.get("References", []),
                    cvss_score=cvss_score,
                    target=target,
                )
            )
    return findings


def get_trivy_version(trivy_bin: str = "trivy") -> str:
    try:
        result = subprocess.run(
            [trivy_bin, "version", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        data = json.loads(result.stdout)
        return data.get("Version", "unknown")
    except Exception:
        return "unknown"


def print_summary_table(result: ScanResult, policy: PolicyEngine) -> None:
    table = Table(title=f"Scan Results: {result.image}", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Blocked by Policy", justify="right")

    for severity in reversed(SEVERITY_ORDER):
        count = result.counts.get(severity, 0)
        blocked = sum(
            1
            for f in result.by_severity.get(severity, [])
            if policy.should_block(f)
        )
        color = SEVERITY_COLORS.get(severity, "")
        table.add_row(
            Text(severity, style=color),
            str(count),
            Text(str(blocked), style="bold red") if blocked else str(blocked),
        )

    console.print(table)
    console.print(
        f"Scan completed in [bold]{result.scan_time:.1f}s[/bold]. "
        f"Trivy {result.trivy_version}."
    )


def should_fail(result: ScanResult, policy: PolicyEngine) -> bool:
    """Return True if the scan should block (non-zero exit)."""
    for finding in result.findings:
        if policy.should_block(finding):
            return True
    return False


@app.command()
def scan(
    image: str = typer.Argument(..., help="Docker image to scan (e.g. nginx:latest)"),
    policy_file: Optional[Path] = typer.Option(
        None, "--policy", "-p", help="Path to policy YAML file"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Directory to write reports"
    ),
    output_format: str = typer.Option(
        "json", "--format", "-f",
        help="Report formats: json, html, sarif (comma-separated)"
    ),
    ci_mode: Optional[str] = typer.Option(
        None, "--ci", help="CI adapter: github, jenkins, gitlab"
    ),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on",
        help="Severities that cause exit code 1 (comma-separated)"
    ),
    trivy_bin: str = typer.Option(
        os.environ.get("SCANNER_TRIVY_BIN", "trivy"), "--trivy-bin"
    ),
    trivy_timeout: int = typer.Option(
        int(os.environ.get("SCANNER_TRIVY_TIMEOUT", "300")), "--timeout"
    ),
    cache_dir: Optional[str] = typer.Option(
        os.environ.get("SCANNER_TRIVY_CACHE_DIR"), "--cache-dir"
    ),
    ignore_unfixed: bool = typer.Option(
        os.environ.get("SCANNER_IGNORE_UNFIXED", "false").lower() == "true",
        "--ignore-unfixed/--no-ignore-unfixed",
    ),
) -> None:
    """Scan a Docker image for CVEs and apply policy-based blocking."""
    console.print(f"[bold]Scanning[/bold] {image}...")

    # Load policy
    policy_config = load_policy(policy_file)

    # Override policy with CLI flags
    if ignore_unfixed:
        policy_config["ignore_unfixed"] = True
    if fail_on:
        policy_config["fail_on"] = [s.strip().upper() for s in fail_on.split(",")]

    policy = PolicyEngine(policy_config)

    # Run Trivy
    start = time.monotonic()
    raw = run_trivy(image, trivy_bin=trivy_bin, timeout=trivy_timeout, cache_dir=cache_dir)
    elapsed = time.monotonic() - start

    trivy_version = get_trivy_version(trivy_bin)

    # Parse findings
    findings = parse_trivy_json(raw, image)
    result = ScanResult(
        image=image,
        scan_time=elapsed,
        findings=findings,
        trivy_version=trivy_version,
    )

    # Apply policy filtering
    filtered_findings = policy.filter(findings)
    result.findings = filtered_findings

    # Print summary
    print_summary_table(result, policy)

    # CI output
    if ci_mode:
        ci_adapter = CIAdapter(ci_mode)
        ci_adapter.emit(filtered_findings)

    # Generate reports
    if output:
        output.mkdir(parents=True, exist_ok=True)
        formats = [f.strip().lower() for f in output_format.split(",")]
        generator = ReportGenerator(image=image, result=result)
        for fmt in formats:
            report_path = generator.write(output, fmt)
            console.print(f"Report: [cyan]{report_path}[/cyan]")

    # Exit decision
    blocking = [f for f in filtered_findings if policy.should_block(f)]
    if blocking:
        console.print(
            f"\n[bold red]SCAN FAILED[/bold red] — "
            f"{len(blocking)} finding(s) exceed policy threshold."
        )
        raise typer.Exit(1)
    else:
        console.print("\n[bold green]SCAN PASSED[/bold green]")
        raise typer.Exit(0)


@app.command("scan-tar")
def scan_tar(
    tar_path: Path = typer.Argument(..., help="Path to docker save tarball"),
    image_name: str = typer.Option(..., "--image-name", help="Name to use in reports"),
    policy_file: Optional[Path] = typer.Option(None, "--policy", "-p"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    output_format: str = typer.Option("json", "--format", "-f"),
    ci_mode: Optional[str] = typer.Option(None, "--ci"),
    fail_on: str = typer.Option("CRITICAL", "--fail-on"),
    trivy_bin: str = typer.Option(
        os.environ.get("SCANNER_TRIVY_BIN", "trivy"), "--trivy-bin"
    ),
    trivy_timeout: int = typer.Option(
        int(os.environ.get("SCANNER_TRIVY_TIMEOUT", "300")), "--timeout"
    ),
) -> None:
    """Scan a saved Docker image tarball (for air-gapped environments)."""
    if not tar_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {tar_path}")
        raise typer.Exit(2)

    console.print(f"[bold]Scanning tarball[/bold] {tar_path} as {image_name}...")

    policy_config = load_policy(policy_file)
    if fail_on:
        policy_config["fail_on"] = [s.strip().upper() for s in fail_on.split(",")]
    policy = PolicyEngine(policy_config)

    start = time.monotonic()
    raw = run_trivy(
        image_name,
        trivy_bin=trivy_bin,
        timeout=trivy_timeout,
        tar_path=str(tar_path),
    )
    elapsed = time.monotonic() - start

    findings = parse_trivy_json(raw, image_name)
    filtered = policy.filter(findings)

    result = ScanResult(
        image=image_name,
        scan_time=elapsed,
        findings=filtered,
        trivy_version=get_trivy_version(trivy_bin),
    )

    print_summary_table(result, policy)

    if ci_mode:
        CIAdapter(ci_mode).emit(filtered)

    if output:
        output.mkdir(parents=True, exist_ok=True)
        formats = [f.strip().lower() for f in output_format.split(",")]
        generator = ReportGenerator(image=image_name, result=result)
        for fmt in formats:
            report_path = generator.write(output, fmt)
            console.print(f"Report: [cyan]{report_path}[/cyan]")

    blocking = [f for f in filtered if policy.should_block(f)]
    if blocking:
        console.print(
            f"\n[bold red]SCAN FAILED[/bold red] — {len(blocking)} finding(s)."
        )
        raise typer.Exit(1)
    else:
        console.print("\n[bold green]SCAN PASSED[/bold green]")
        raise typer.Exit(0)


if __name__ == "__main__":
    app()
