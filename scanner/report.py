"""
Report generation: HTML, SARIF, and JSON.

SARIF output is compatible with GitHub Code Scanning (upload-sarif action).
HTML output uses Jinja2 with an embedded template.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

try:
    from jinja2 import Environment, BaseLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

if TYPE_CHECKING:
    from scanner.main import Finding, ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

SEVERITY_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "none",
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 0; padding: 20px; background: #f6f8fa; color: #24292e; }
  h1 { border-bottom: 2px solid #e1e4e8; padding-bottom: 10px; }
  .meta { color: #586069; font-size: 0.9em; margin-bottom: 20px; }
  .summary { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
  .badge { padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 0.9em; }
  .critical { background: #ffeef0; color: #cb2431; border: 1px solid #f97583; }
  .high     { background: #fff5b1; color: #b08800; border: 1px solid #e3b341; }
  .medium   { background: #fffbdd; color: #735c0f; border: 1px solid #f9c513; }
  .low      { background: #e8f5e9; color: #2e7d32; border: 1px solid #66bb6a; }
  .unknown  { background: #f6f8fa; color: #586069; border: 1px solid #e1e4e8; }
  .findings { margin-top: 20px; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th { background: #f6f8fa; padding: 10px 14px; text-align: left;
       font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.04em; }
  td { padding: 10px 14px; border-top: 1px solid #e1e4e8; font-size: 0.9em;
       vertical-align: top; }
  tr:hover td { background: #f6f8fa; }
  .sev-CRITICAL { color: #cb2431; font-weight: bold; }
  .sev-HIGH     { color: #b08800; font-weight: bold; }
  .sev-MEDIUM   { color: #735c0f; }
  .sev-LOW      { color: #2e7d32; }
  .sev-UNKNOWN  { color: #586069; }
  .fixable { color: #28a745; font-size: 0.8em; }
  .no-fix  { color: #586069; font-size: 0.8em; }
  code { background: #f6f8fa; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }
  .pass { color: #28a745; font-weight: bold; }
  .fail { color: #cb2431; font-weight: bold; }
</style>
</head>
<body>
<h1>{{ title }}</h1>
<div class="meta">
  Image: <strong>{{ image }}</strong> &nbsp;|&nbsp;
  Scanned: {{ scan_time }} &nbsp;|&nbsp;
  Duration: {{ duration }}s &nbsp;|&nbsp;
  Trivy: {{ trivy_version }}
</div>

<div class="summary">
  {% for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] %}
  <div class="badge {{ sev.lower() }}">
    {{ sev }}: {{ counts.get(sev, 0) }}
  </div>
  {% endfor %}
</div>

{% if findings %}
<div class="findings">
  <table>
    <thead>
      <tr>
        <th>CVE</th>
        <th>Severity</th>
        <th>Package</th>
        <th>Installed</th>
        <th>Fixed In</th>
        <th>Title</th>
        <th>Target</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr>
        <td><code>{{ f.vulnerability_id }}</code></td>
        <td><span class="sev-{{ f.severity }}">{{ f.severity }}</span></td>
        <td><code>{{ f.pkg_name }}</code></td>
        <td><code>{{ f.installed_version }}</code></td>
        <td>
          {% if f.fixed_version %}
            <code class="fixable">{{ f.fixed_version }}</code>
          {% else %}
            <span class="no-fix">No fix available</span>
          {% endif %}
        </td>
        <td>{{ f.title or f.description[:100] or "—" }}</td>
        <td><code>{{ f.target }}</code></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% else %}
<p class="pass">No findings after policy filtering.</p>
{% endif %}
</body>
</html>
""".strip()


def _sanitise_image_name(image: str) -> str:
    """Convert image:tag to a safe filename segment."""
    return re.sub(r"[^\w\-.]", "-", image)


class ReportGenerator:
    """Generate reports in multiple formats from a ScanResult."""

    def __init__(self, image: str, result: "ScanResult") -> None:
        self.image = image
        self.result = result
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def write(self, output_dir: Path, fmt: str) -> Path:
        """Write a report in the given format and return its path."""
        fmt = fmt.lower().strip()
        safe_name = _sanitise_image_name(self.image)
        filename = f"scan-{safe_name}.{fmt}"
        path = output_dir / filename

        if fmt == "json":
            path.write_text(self._render_json(), encoding="utf-8")
        elif fmt == "sarif":
            path.write_text(self._render_sarif(), encoding="utf-8")
        elif fmt == "html":
            path.write_text(self._render_html(), encoding="utf-8")
        else:
            raise ValueError(f"Unknown report format: {fmt!r}. Use json, sarif, or html.")

        return path

    def _render_json(self) -> str:
        data = {
            "schema_version": "1.0",
            "image": self.image,
            "scan_timestamp": self.timestamp,
            "scan_duration_seconds": round(self.result.scan_time, 2),
            "trivy_version": self.result.trivy_version,
            "summary": self.result.counts,
            "findings": [f.to_dict() for f in self.result.findings],
        }
        return json.dumps(data, indent=2)

    def _render_sarif(self) -> str:
        rules: list[dict] = []
        results: list[dict] = []
        seen_rules: set[str] = set()

        for finding in self.result.findings:
            rule_id = finding.vulnerability_id
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                help_uri = (
                    finding.references[0]
                    if finding.references
                    else f"https://nvd.nist.gov/vuln/detail/{rule_id}"
                )
                rules.append({
                    "id": rule_id,
                    "name": f"CVE_{rule_id.replace('-', '_')}",
                    "shortDescription": {"text": finding.title or rule_id},
                    "fullDescription": {
                        "text": finding.description or finding.title or rule_id
                    },
                    "helpUri": help_uri,
                    "properties": {
                        "tags": ["security", "vulnerability", finding.severity.lower()],
                        "security-severity": str(finding.cvss_score or ""),
                    },
                })

            sarif_level = SEVERITY_TO_SARIF.get(finding.severity.upper(), "warning")
            fix_text = (
                f"Upgrade {finding.pkg_name} to {finding.fixed_version}."
                if finding.fixed_version
                else f"No fix available for {finding.pkg_name} {finding.installed_version}."
            )
            results.append({
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {
                    "text": (
                        f"{finding.severity} CVE in {finding.pkg_name} "
                        f"{finding.installed_version}. {fix_text} "
                        f"{finding.title}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.target or self.image,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "cvss_score": finding.cvss_score,
                    "package": finding.pkg_name,
                    "installed_version": finding.installed_version,
                    "fixed_version": finding.fixed_version,
                },
            })

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "container-security-scanner",
                            "version": "1.0.0",
                            "informationUri": (
                                "https://github.com/barry-oyoung/container-security-scanner"
                            ),
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "image": self.image,
                        "scanTimestamp": self.timestamp,
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _render_html(self) -> str:
        counts = self.result.counts
        findings_sorted = sorted(
            self.result.findings,
            key=lambda f: (
                -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}.get(
                    f.severity, 0
                ),
                f.pkg_name,
            ),
        )

        if JINJA2_AVAILABLE:
            env = Environment(loader=BaseLoader())
            tmpl = env.from_string(HTML_TEMPLATE)
            return tmpl.render(
                title="Container Security Scan Report",
                image=self.image,
                scan_time=self.timestamp[:19].replace("T", " ") + " UTC",
                duration=round(self.result.scan_time, 1),
                trivy_version=self.result.trivy_version or "unknown",
                counts=counts,
                findings=findings_sorted,
            )
        else:
            # Fallback: minimal HTML without Jinja2
            rows = "".join(
                f"<tr><td>{f.vulnerability_id}</td><td>{f.severity}</td>"
                f"<td>{f.pkg_name}</td><td>{f.installed_version}</td>"
                f"<td>{f.fixed_version or 'No fix'}</td><td>{f.title or ''}</td></tr>"
                for f in findings_sorted
            )
            summary = " | ".join(f"{k}: {v}" for k, v in counts.items())
            return (
                f"<html><body><h1>Scan: {self.image}</h1>"
                f"<p>{summary}</p>"
                f"<table border='1'>{rows}</table></body></html>"
            )
