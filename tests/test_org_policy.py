"""Org policy: the paid path, and the promise it must not break.

The load-bearing test in this file is ``test_no_terraform_is_ever_uploaded``.
Everything else about this feature is a convenience; that one is the reason
anyone installs a security tool from a vendor they have not audited. If it ever
fails, the product is not shippable regardless of what else passes.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from sovereign_mcp import org
from sovereign_mcp.tools import org_policy
from sovereign_mcp.tools.scan import run_scan

# Fixtures live beside the tests so this package's suite runs in a standalone
# checkout — the public MCP repository has no demo-iac-pr/ directory.
FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE = FIXTURES / "vulnerable.tf"

ORG_RULES = [
    {
        "id": "ACME-1",
        "title": "Databases must retain backups for a year",
        "service": "rds",
        "resource_type": "rds_instance",
        "severity": "High",
        "provider": "aws",
        "policy_name": "Acme Data Retention",
        "condition": {
            "type": "comparison",
            "expression": {
                "attribute": "backup_retention_period",
                "operator": "ge",
                "value": 365,
            },
        },
    },
    {
        "id": "ACME-2",
        "title": "No SSH from the internet",
        "service": "ec2",
        "resource_type": "security_group",
        "severity": "Critical",
        "provider": "aws",
        "policy_name": "Acme Network Baseline",
        "condition": {
            "type": "list_forbidden_match",
            "expression": {
                "attribute": "ingress",
                "key": "cidr_blocks",
                "pattern": "0.0.0.0/0",
            },
        },
    },
]

PAYLOAD = {
    "org_name": "Acme",
    "policy_version": "abc123",
    "rule_count": len(ORG_RULES),
    "providers": ["aws"],
    "rules": ORG_RULES,
}


@pytest.fixture
def connected(monkeypatch):
    """Simulate a connected org without touching the network."""
    monkeypatch.setenv("SOVEREIGN_TOKEN", "test-token")
    org.clear_cache()
    monkeypatch.setattr(org, "fetch_policy", lambda force=False: PAYLOAD)
    yield
    org.clear_cache()


@pytest.fixture
def disconnected(monkeypatch):
    monkeypatch.delenv("SOVEREIGN_TOKEN", raising=False)
    monkeypatch.delenv("SOVEREIGN_PR_TOKEN", raising=False)
    org.clear_cache()
    yield
    org.clear_cache()


# ── the promise ──────────────────────────────────────────────────────────────

def test_no_terraform_is_ever_uploaded(monkeypatch):
    """Rules come down; code never goes up.

    Asserted at the transport: every request this package makes must be a GET
    with no body. If org policy ever starts POSTing the developer's Terraform,
    this fails.
    """
    captured = []

    class _Response:
        def read(self):
            return json.dumps(PAYLOAD).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _fake_urlopen(request, timeout=None):
        captured.append(request)
        return _Response()

    monkeypatch.setenv("SOVEREIGN_TOKEN", "test-token")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    org.clear_cache()

    run_scan(files={"main.tf": FIXTURE.read_text(encoding="utf-8")})

    assert captured, "expected the org-policy fetch to happen"
    for request in captured:
        assert request.get_method() == "GET"
        assert request.data is None, "a request carried a body — check for code upload"
        assert "org-policy" in request.full_url
    org.clear_cache()


def test_nothing_leaves_the_machine_when_unconnected(monkeypatch, disconnected):
    """The free tier must make no network call at all."""
    def _explode(*args, **kwargs):
        raise AssertionError("unconnected install attempted a network call")

    monkeypatch.setattr(urllib.request, "urlopen", _explode)

    result = run_scan(files={"main.tf": FIXTURE.read_text(encoding="utf-8")})
    assert result["findings_count"] > 0
    assert all(f["source"] == "builtin" for f in result["findings"])


# ── pre-generation requirements: the actual product ──────────────────────────

def test_requirements_are_phrased_as_instructions_not_conditions(connected):
    result = org_policy.requirements(resource_type="aws_db_instance")

    assert result["connected"] is True
    assert result["org_name"] == "Acme"
    requirement = result["requirements"][0]
    assert requirement["id"] == "ACME-1"
    # The model needs a sentence it can act on, not a serialized condition.
    assert requirement["requirement"] == "`backup_retention_period` must be at least 365."
    assert requirement["policy"] == "Acme Data Retention"


def test_requirements_filter_to_the_resource_being_written(connected):
    result = org_policy.requirements(resource_type="aws_security_group")

    assert [r["id"] for r in result["requirements"]] == ["ACME-2"]
    assert "No entry in `ingress[].cidr_blocks`" in result["requirements"][0]["requirement"]


def test_unknown_resource_type_says_so_without_implying_no_policy(connected):
    result = org_policy.requirements(resource_type="aws_sqs_queue")

    assert result["requirements"] == []
    assert result["total_org_rules"] == 2
    assert "none scoped to" in result["note"]


def test_unconnected_requirements_explain_rather_than_error(disconnected):
    result = org_policy.requirements(resource_type="aws_db_instance")

    assert result["connected"] is False
    assert result["requirements"] == []
    assert "SOVEREIGN_TOKEN" in result["note"]


# ── condition rendering ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "condition,expected",
    [
        ({"type": "boolean", "expression": {"attribute": "encrypted", "value": True}},
         "`encrypted` must be `true`."),
        ({"type": "list_match_any",
          "expression": {"attribute": "region", "value": ["eu-west-1", "eu-central-1"]}},
         "`region` must be one of: eu-west-1, eu-central-1."),
        ({"type": "negative_regex", "expression": {"attribute": "name", "pattern": "^tmp"}},
         "`name` must NOT match `^tmp`."),
        ({"type": "manual"},
         "Requires human review — this control cannot be verified from Terraform alone."),
    ],
)
def test_condition_rendering(condition, expected):
    assert org_policy.describe_condition(condition) == expected


# ── failure handling ─────────────────────────────────────────────────────────

def test_a_rejected_token_never_breaks_the_scan(monkeypatch):
    """Built-in rules are the floor. Policy problems must not remove it."""
    monkeypatch.setenv("SOVEREIGN_TOKEN", "bad-token")
    org.clear_cache()

    def _unauthorized(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", _unauthorized)

    result = run_scan(files={"main.tf": FIXTURE.read_text(encoding="utf-8")})
    assert result["findings_count"] > 0

    status = org_policy.connection_status()
    assert status["connected"] is False
    assert "Generate a new org token" in status["error"]
    org.clear_cache()


def test_unreachable_api_degrades_to_local_rules(monkeypatch):
    monkeypatch.setenv("SOVEREIGN_TOKEN", "test-token")
    org.clear_cache()

    def _unreachable(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _unreachable)

    result = run_scan(files={"main.tf": FIXTURE.read_text(encoding="utf-8")})
    assert result["findings_count"] > 0
    assert org_policy.evaluate({"main.tf": "resource \"aws_s3_bucket\" \"b\" {}"}) == []
    org.clear_cache()


def test_status_distinguishes_local_from_org_mode(connected):
    status = org_policy.connection_status()

    assert status["connected"] is True
    assert status["mode"] == "org"
    assert status["org_name"] == "Acme"
    assert status["rule_count"] == 2


# ── the loop that makes this a product, not a scanner ────────────────────────

VIOLATING_TF = '''resource "aws_db_instance" "prod" {
  engine                  = "postgres"
  backup_retention_period = 7
}
'''


def test_an_org_rule_actually_fires_against_real_hcl(connected):
    """The whole feature, asserted end to end.

    Rules are fetched, evaluated locally against Terraform the org never sent
    anywhere, and reported as the org's own — not as a built-in finding.
    """
    findings = org_policy.evaluate({"main.tf": VIOLATING_TF}, provider="aws")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["check_id"] == "ACME-1"
    assert finding["severity"] == "High"
    assert finding["source"] == "org_policy"
    assert finding["resource"] == "aws_db_instance.prod"
    assert "your organization's policy" in finding["why"]


def test_satisfying_the_requirement_clears_the_violation(connected):
    compliant = VIOLATING_TF.replace("= 7", "= 365")

    assert org_policy.evaluate({"main.tf": compliant}, provider="aws") == []


def test_org_findings_surface_in_the_scan_alongside_builtin_ones(connected):
    result = run_scan(files={"main.tf": VIOLATING_TF})

    sources = {f["source"] for f in result["findings"]}
    assert sources == {"builtin", "org_policy"}
    assert result["org_policy_violations"] == 1
    assert "your organization's own rules" in result["org_policy_note"]


def test_terraform_and_inventory_vocabularies_both_resolve(connected):
    """An assistant says aws_db_instance; a policy author writes rds_instance."""
    by_terraform = org_policy.requirements(resource_type="aws_db_instance")
    by_inventory = org_policy.requirements(resource_type="rds_instance")

    assert [r["id"] for r in by_terraform["requirements"]] == ["ACME-1"]
    assert [r["id"] for r in by_inventory["requirements"]] == ["ACME-1"]


def test_inventory_key_mapping_is_derived_not_guessed():
    assert org_policy.inventory_key_for("aws_db_instance") == "rds_instance"
    assert org_policy.inventory_key_for("aws_s3_bucket") == "s3_bucket"
    assert org_policy.inventory_key_for("not_a_real_resource") is None


def test_manual_rules_are_not_evaluated_against_terraform(connected, monkeypatch):
    """A control needing human review cannot fail a scan."""
    manual = [{
        "id": "ACME-9", "title": "Annual access review", "service": "iam",
        "resource_type": "rds_instance", "severity": "High", "provider": "aws",
        "condition": {"type": "manual"},
    }]
    monkeypatch.setattr(
        org, "fetch_policy", lambda force=False: {"org_name": "Acme", "rules": manual}
    )

    assert org_policy.evaluate({"main.tf": VIOLATING_TF}, provider="aws") == []
