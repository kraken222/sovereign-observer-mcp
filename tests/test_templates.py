"""Templates must be secure *now*, not secure when they were written.

``secure_template`` tells the assistant these contain no Critical or High
findings. That claim has to be enforced by something, or it decays silently the
next time Checkov adds a policy — and a security tool making a stale guarantee
is worse than one making no guarantee.

So every template is scanned here with the same engine the product uses. If a
policy update breaks one, this test fails and the template gets fixed.
"""
from __future__ import annotations

import pytest

from sovereign_mcp.tools import templates
from sovereign_mcp.tools.scan import run_scan


@pytest.mark.parametrize("resource_type", templates.available())
def test_template_has_no_blocking_findings(resource_type: str):
    entry = templates.get_template(resource_type)
    assert "error" not in entry, entry

    result = run_scan(files={"main.tf": entry["terraform"]})
    blocking = [
        (f["check_id"], f["severity"], f["title"])
        for f in result["findings"]
        if f["severity"] in ("Critical", "High")
    ]

    assert blocking == [], (
        f"{resource_type} template is no longer clean — the engine now reports "
        f"{blocking}. Fix the template; do not weaken this test."
    )


@pytest.mark.parametrize("resource_type", templates.available())
def test_template_documents_what_it_leaves_to_the_user(resource_type: str):
    """A template that silently skips context-dependent controls is a trap."""
    entry = templates.get_template(resource_type)

    assert entry["notes"], f"{resource_type} has no notes"
    assert entry["description"]
    assert entry["terraform"].strip()


def test_unknown_resource_type_points_somewhere_useful():
    result = templates.get_template("aws_lambda_function")

    assert "error" in result
    assert result["available"]
    # An unknown type must not dead-end — scanning still covers it.
    assert "scan_terraform" in result["next_step"]


def test_aliases_resolve_to_the_same_template():
    assert templates.get_template("s3")["terraform"] == (
        templates.get_template("aws_s3_bucket")["terraform"]
    )
    assert templates.get_template("RDS")["resource_type"] == "aws_db_instance"
