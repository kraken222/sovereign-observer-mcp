"""Golden-file tests against the shared demo fixtures.

``demo-iac-pr/main.tf`` and ``main.fixed.tf`` are the same pair the GitHub Action
smoke test and the demo recording use, so pinning the MCP against them keeps all
three tellings of the story consistent.

Note what the "fixed" fixture actually asserts. It does **not** produce zero
findings — it produces 16, all Medium and below (logging, versioning, lifecycle
hygiene). What it clears is every Critical and High, which is exactly what the
merge gate keys on. Asserting "zero findings" here would be asserting something
false, and would break the moment Checkov adds a hygiene policy.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sovereign_mcp.tools.scan import run_scan

# Fixtures live beside the tests so this suite runs in a standalone checkout.
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Findings the vulnerable fixture must always trip. Kept to the ones the fixture
# exists to demonstrate — a broader list would fail on every Checkov bump for
# reasons that have nothing to do with this package.
EXPECTED_IN_VULNERABLE = {
    "CKV_AWS_17",   # RDS publicly accessible          (Critical)
    "CKV_AWS_24",   # SG ingress 0.0.0.0/0 -> port 22  (Critical)
    "CKV_AWS_16",   # RDS not encrypted at rest        (High)
}


def _read(name: str) -> dict:
    path = FIXTURES / name
    if not path.is_file():
        pytest.skip(f"fixture not available: {path}")
    return {"main.tf": path.read_text(encoding="utf-8")}


def test_vulnerable_fixture_trips_the_known_findings():
    result = run_scan(files=_read("vulnerable.tf"))
    found = {f["check_id"] for f in result["findings"]}

    missing = EXPECTED_IN_VULNERABLE - found
    assert not missing, f"engine stopped detecting: {sorted(missing)}"
    assert result["summary"]["critical"] >= 2
    assert result["scanned_files"] == 1


def test_fixed_fixture_clears_every_blocking_finding():
    result = run_scan(files=_read("hardened.tf"))

    assert result["summary"]["critical"] == 0
    assert result["summary"]["high"] == 0

    blocking = [
        f for f in result["findings"] if f["severity"] in ("Critical", "High")
    ]
    assert blocking == [], f"unexpected blocking findings: {blocking}"


def test_empty_input_explains_itself_rather_than_returning_zero():
    """An empty scan must never look like a clean scan.

    A security tool that silently returns "0 findings" when it was handed
    nothing is actively dangerous — the assistant would report the code as safe.
    """
    result = run_scan(files={})

    assert result["findings_count"] == 0
    assert "note" in result
    assert "No Terraform sources" in result["note"]


def test_findings_are_ordered_most_severe_first():
    result = run_scan(files=_read("vulnerable.tf"))
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    severities = [rank[f["severity"]] for f in result["findings"]]

    assert severities == sorted(severities)


def test_output_is_capped_to_protect_assistant_context():
    from sovereign_mcp.tools import scan

    result = run_scan(files=_read("vulnerable.tf"))

    assert len(result["findings"]) <= scan.MAX_FINDINGS_RETURNED
    if result["findings_count"] > scan.MAX_FINDINGS_RETURNED:
        assert result["truncated"] is True
