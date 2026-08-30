"""Compliance mapping must stay evidence, never an attestation.

The mapping is commercially the most valuable thing in this package and legally
the most dangerous. These tests pin the guardrails: the caveat is always
present, NCA identifiers are always flagged provisional, unmappable checks are
omitted rather than guessed, and an empty result never reads as a pass.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sovereign_mcp.tools.compliance import check_compliance, coverage
from sovereign_mcp.tools.scan import run_scan

# Fixtures live beside the tests so this package's suite runs in a standalone
# checkout — the public MCP repository has no demo-iac-pr/ directory.
FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE = FIXTURES / "vulnerable.tf"


@pytest.fixture(scope="module")
def findings():
    if not FIXTURE.is_file():
        pytest.skip("demo fixture not available")
    return run_scan(files={"main.tf": FIXTURE.read_text(encoding="utf-8")})["findings"]


def test_maps_to_the_regional_frameworks_nobody_else_offers(findings):
    result = check_compliance(findings=findings)

    for framework in ("DORA", "NIS2", "NCA-CCC", "NESA-IAS"):
        assert framework in result["frameworks"], f"{framework} missing"
        assert result["frameworks"][framework]["controls_touched"] > 0


def test_maps_to_the_audit_crosswalk_too(findings):
    result = check_compliance(findings=findings)

    for framework in ("SOC2", "ISO27001", "NIST", "PCI"):
        assert framework in result["frameworks"]


def test_nca_is_always_flagged_provisional(findings):
    """The control numbers are not reconciled yet. Never present them as final."""
    result = check_compliance(findings=findings)
    nca = result["frameworks"]["NCA-CCC"]

    assert nca["provisional"] is True
    assert "provisional" in nca["provisional_note"].lower()
    assert "subdomain name" in nca["provisional_note"]


def test_caveat_is_never_omitted(findings):
    for result in (
        check_compliance(findings=findings),
        check_compliance(findings=[]),
    ):
        assert "not a compliance assessment" in result["caveat"]
        assert "governance" in result["caveat"]


def test_no_findings_does_not_read_as_compliant():
    """The dangerous failure mode: zero gaps presented as a pass."""
    result = check_compliance(findings=[])

    assert result["frameworks"] == {}
    assert "not that the frameworks are met" in result["note"]


def test_framework_filter_is_respected(findings):
    result = check_compliance(findings=findings, frameworks=["DORA"])

    assert set(result["frameworks"]) == {"DORA"}


def test_can_scan_and_map_in_one_call():
    result = check_compliance(files={"main.tf": FIXTURE.read_text(encoding="utf-8")})

    assert result["findings_mapped"] > 0
    assert "DORA" in result["frameworks"]


def test_coverage_reports_what_cannot_be_evidenced():
    """A coverage number is only honest next to what it excludes."""
    result = coverage("DORA")

    assert result["evidenced_count"] < result["total_count"]
    not_evidenced = [a for a in result["articles"] if a["status"] == "not-evidenced"]
    assert not_evidenced, "DORA has governance articles no scanner can evidence"


def test_coverage_rejects_non_regulatory_frameworks():
    result = coverage("SOC2")

    assert "error" in result
    assert "DORA" in result["available"]


def test_requires_some_input():
    assert "error" in check_compliance()
