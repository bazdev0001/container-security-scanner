"""
Policy engine for CVE filtering.

Supports:
- Severity thresholds
- Permanent CVE ignore lists
- Time-boxed exceptions with audit trail
- ignore_unfixed mode (skip CVEs with no available fix)
- Path-based ignores
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import yaml

if TYPE_CHECKING:
    from scanner.main import Finding

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DEFAULT_POLICY: dict = {
    "severity_threshold": "CRITICAL",
    "ignore_unfixed": False,
    "fail_on": ["CRITICAL"],
    "ignore_cves": [],
    "exceptions": [],
    "ignore_paths": [],
}


def load_policy(policy_file: Optional[Path]) -> dict:
    """Load policy from YAML file, falling back to defaults."""
    policy = dict(DEFAULT_POLICY)

    # Check env var fallback
    if policy_file is None:
        env_path = Path("policy.yaml")
        if env_path.exists():
            policy_file = env_path

    if policy_file is not None:
        if not policy_file.exists():
            logger.warning("Policy file not found: %s — using defaults", policy_file)
            return policy
        with open(policy_file) as f:
            loaded = yaml.safe_load(f) or {}
        # Merge, not replace
        policy.update({k: v for k, v in loaded.items() if v is not None})
        logger.debug("Loaded policy from %s", policy_file)

    return policy


class PolicyException:
    """A time-boxed exception for a specific CVE."""

    def __init__(self, data: dict) -> None:
        self.cve_id: str = data["cve_id"]
        self.reason: str = data.get("reason", "")
        self.approved_by: str = data.get("approved_by", "")
        self.ticket: str = data.get("ticket", "")
        self._expires_raw: Optional[str] = data.get("expires")

    @property
    def expires(self) -> Optional[date]:
        if self._expires_raw is None:
            return None
        try:
            return datetime.strptime(self._expires_raw, "%Y-%m-%d").date()
        except ValueError:
            logger.warning("Invalid expiry date for %s: %s", self.cve_id, self._expires_raw)
            return None

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return date.today() > self.expires

    def __repr__(self) -> str:
        expiry = str(self.expires) if self.expires else "never"
        return f"<PolicyException {self.cve_id} expires={expiry}>"


class PolicyEngine:
    """
    Applies organisation policy to a list of CVE findings.

    Filtering priority (highest to lowest):
    1. Path-based ignores (entire target paths)
    2. Permanent CVE ignore list
    3. Active (non-expired) exceptions
    4. ignore_unfixed: drop CVEs that have no fix
    5. Severity threshold: drop below threshold
    """

    def __init__(self, config: dict) -> None:
        self.config = {**DEFAULT_POLICY, **config}
        self._fail_on: set[str] = {
            s.upper() for s in self.config.get("fail_on", ["CRITICAL"])
        }
        self._ignore_cves: set[str] = set(self.config.get("ignore_cves", []))
        self._ignore_paths: list[str] = self.config.get("ignore_paths", [])
        self._ignore_unfixed: bool = bool(self.config.get("ignore_unfixed", False))
        self._threshold_rank: int = SEVERITY_RANK.get(
            self.config.get("severity_threshold", "CRITICAL").upper(), 4
        )

        self._exceptions: dict[str, PolicyException] = {}
        self._expired_exceptions: list[PolicyException] = []
        for exc_data in self.config.get("exceptions", []):
            exc = PolicyException(exc_data)
            if exc.is_expired:
                self._expired_exceptions.append(exc)
                logger.warning(
                    "Exception for %s expired on %s (ticket: %s). "
                    "Finding will now be enforced.",
                    exc.cve_id,
                    exc.expires,
                    exc.ticket or "n/a",
                )
            else:
                self._exceptions[exc.cve_id] = exc

    def filter(self, findings: list["Finding"]) -> list["Finding"]:
        """
        Apply all policy rules and return findings that remain after filtering.

        Note: filtered OUT means suppressed/allowed. What remains is what
        the scanner reports as active findings for threshold evaluation.
        """
        result = []
        for finding in findings:
            decision = self._evaluate(finding)
            if decision == "keep":
                result.append(finding)
            else:
                logger.debug(
                    "Suppressed %s (%s/%s): %s",
                    finding.vulnerability_id,
                    finding.pkg_name,
                    finding.severity,
                    decision,
                )
        return result

    def _evaluate(self, finding: "Finding") -> str:
        """
        Return 'keep' if the finding should be reported, or a reason string
        explaining why it was suppressed.
        """
        # 1. Path-based ignores
        for ignored_path in self._ignore_paths:
            if finding.target.startswith(ignored_path):
                return f"path_ignored:{ignored_path}"

        # 2. Permanent ignore list
        if finding.vulnerability_id in self._ignore_cves:
            return f"cve_ignored:{finding.vulnerability_id}"

        # 3. Active exception
        if finding.vulnerability_id in self._exceptions:
            exc = self._exceptions[finding.vulnerability_id]
            return f"exception:{exc.cve_id} (approved_by={exc.approved_by})"

        # 4. Unfixed filter
        if self._ignore_unfixed and not finding.has_fix:
            return "unfixed"

        # 5. Below severity threshold
        finding_rank = SEVERITY_RANK.get(finding.severity.upper(), 0)
        if finding_rank < self._threshold_rank:
            return f"below_threshold:{finding.severity}"

        return "keep"

    def should_block(self, finding: "Finding") -> bool:
        """
        Return True if this finding should cause CI to fail.
        Uses fail_on set, not threshold — a finding may be reported
        at MEDIUM severity without blocking.
        """
        return finding.severity.upper() in self._fail_on

    @property
    def expired_exceptions(self) -> list[PolicyException]:
        """Return exceptions that have passed their expiry date."""
        return list(self._expired_exceptions)

    @property
    def active_exceptions(self) -> list[PolicyException]:
        """Return currently active exceptions."""
        return list(self._exceptions.values())

    def summary(self) -> dict:
        """Return a human-readable summary of active policy configuration."""
        return {
            "severity_threshold": self.config.get("severity_threshold"),
            "fail_on": sorted(self._fail_on),
            "ignore_unfixed": self._ignore_unfixed,
            "ignore_cves_count": len(self._ignore_cves),
            "active_exceptions_count": len(self._exceptions),
            "expired_exceptions_count": len(self._expired_exceptions),
            "ignore_paths": self._ignore_paths,
        }
