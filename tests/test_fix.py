"""``apply_fixes`` must stay as conservative as the CI flow it shares code with.

The applier itself is covered by ``backend/tests/test_autofix_applier.py``. What
is tested here is the gate in front of it — the part this package adds, and the
part that would let an unsafe fix through if it were wrong.
"""
from __future__ import annotations

from sovereign_mcp.tools.fix import apply_fixes

VULNERABLE_RDS = '''resource "aws_db_instance" "prod" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
}
'''


def test_applies_an_allowlisted_fix():
    result = apply_fixes(
        VULNERABLE_RDS,
        [{"check_id": "CKV_AWS_17", "resource_address": "aws_db_instance.prod"}],
    )

    assert result["modified"] is True
    assert "publicly_accessible = false" in result["content"]
    assert result["applied"][0]["check_id"] == "CKV_AWS_17"
    assert result["skipped"] == []


def test_adds_a_missing_attribute():
    result = apply_fixes(
        VULNERABLE_RDS,
        [{"check_id": "CKV_AWS_16", "resource_address": "aws_db_instance.prod"}],
    )

    assert "storage_encrypted = true" in result["content"]


def test_refuses_checks_outside_the_allowlist():
    """The allowlist is the safety property. Anything else stays advisory."""
    result = apply_fixes(
        VULNERABLE_RDS,
        # Public-access-block checks add whole resources — never auto-applied.
        [{"check_id": "CKV_AWS_53", "resource_address": "aws_s3_bucket.data"}],
    )

    assert result["modified"] is False
    assert result["applied"] == []
    assert "allowlist" in result["skipped"][0]["reason"]


def test_never_overwrites_a_deliberate_expression():
    """A value wired to a variable is a human decision, not a misconfiguration."""
    src = '''resource "aws_db_instance" "prod" {
  engine              = "postgres"
  publicly_accessible = var.is_public
}
'''
    result = apply_fixes(
        src, [{"check_id": "CKV_AWS_17", "resource_address": "aws_db_instance.prod"}]
    )

    assert result["modified"] is False
    assert "var.is_public" in result["content"]
    assert result["skipped"]


def test_holds_back_fixes_on_meta_loop_resources():
    """Checkov mis-evaluates count/for_each/dynamic — a fix there can break prod."""
    src = '''resource "aws_db_instance" "prod" {
  count               = var.enabled ? 1 : 0
  engine              = "postgres"
  publicly_accessible = true
}
'''
    result = apply_fixes(
        src, [{"check_id": "CKV_AWS_17", "resource_address": "aws_db_instance.prod"}]
    )

    assert result["modified"] is False
    assert "for_each" in result["skipped"][0]["reason"]


def test_applies_several_fixes_in_one_pass():
    result = apply_fixes(
        VULNERABLE_RDS,
        [
            {"check_id": "CKV_AWS_17", "resource_address": "aws_db_instance.prod"},
            {"check_id": "CKV_AWS_16", "resource_address": "aws_db_instance.prod"},
            {"check_id": "CKV_AWS_293", "resource_address": "aws_db_instance.prod"},
        ],
    )

    assert len(result["applied"]) == 3
    assert "publicly_accessible = false" in result["content"]
    assert "storage_encrypted = true" in result["content"]
    assert "deletion_protection = true" in result["content"]


def test_fixed_output_actually_clears_the_findings():
    """The point of the tool, asserted end to end rather than by inspection."""
    from sovereign_mcp.tools.scan import run_scan

    before = run_scan(files={"main.tf": VULNERABLE_RDS})
    auto = [
        {"check_id": f["check_id"], "resource_address": f["resource"]}
        for f in before["findings"]
        if f["auto_fixable"]
    ]
    assert auto, "fixture should have auto-fixable findings"

    patched = apply_fixes(VULNERABLE_RDS, auto)
    after = run_scan(files={"main.tf": patched["content"]})

    cleared = {f["check_id"] for f in before["findings"]} - {
        f["check_id"] for f in after["findings"]
    }
    assert cleared == {f["check_id"] for f in auto}


def test_rejects_empty_input():
    assert "error" in apply_fixes("", [{"check_id": "CKV_AWS_17"}])
    assert "error" in apply_fixes(VULNERABLE_RDS, [])
