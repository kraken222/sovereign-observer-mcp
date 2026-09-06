"""The credential-in-source check, seen from the assistant's side.

The backend suite pins the detection itself. What matters here is the path an
assistant actually walks: the finding has to arrive at the top of a scan, and
``explain_finding`` has to say plainly that there is no mechanical fix — because
an assistant told only "advisory" will cheerfully invent one.
"""
from __future__ import annotations

from sovereign_mcp.tools.explain import explain
from sovereign_mcp.tools.scan import run_scan

CHECK_ID = "SOV_SECRET_1"

LEAKY = """
provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  username            = "admin"
  password            = "hunter2"
  storage_encrypted   = true
  publicly_accessible = false
}

resource "aws_db_instance" "billing" {
  identifier          = "billing"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  password            = var.billing_password
  storage_encrypted   = true
  publicly_accessible = false
}
"""


def test_a_hardcoded_password_outranks_the_hygiene_findings():
    """It must survive the context cap. A Critical that gets truncated away
    because twenty Low findings came first is a Critical nobody sees."""
    result = run_scan(files={"main.tf": LEAKY})

    secrets = [f for f in result["findings"] if f["check_id"] == CHECK_ID]
    assert len(secrets) == 1, "expected exactly the one literal credential"

    finding = secrets[0]
    assert finding["severity"] == "Critical"
    assert finding["resource"] == "aws_db_instance.orders"
    assert result["findings"][0]["check_id"] == CHECK_ID


def test_a_referenced_secret_does_not_produce_a_finding():
    """The check is only worth shipping if `var.billing_password` stays quiet."""
    result = run_scan(files={"main.tf": LEAKY})

    flagged = {
        f["resource"] for f in result["findings"] if f["check_id"] == CHECK_ID
    }
    assert "aws_db_instance.billing" not in flagged


def test_the_scan_line_does_not_carry_the_credential():
    result = run_scan(files={"main.tf": LEAKY})

    assert "hunter2" not in repr(result)


def test_explain_refuses_to_offer_a_mechanical_fix_and_says_why():
    detail = explain(CHECK_ID, "aws_db_instance.orders")

    assert detail["auto_fixable"] is False
    # The specific reason, not the generic "adds new resources" boilerplate.
    assert "rotat" in detail["auto_fix_note"].lower()
    assert "adds new resources" not in detail["auto_fix_note"]


def test_explain_gives_both_a_variable_and_a_secret_manager_route():
    detail = explain(CHECK_ID, "aws_db_instance.orders")
    tf = detail["terraform"]

    assert 'variable "orders_password"' in tf
    assert "sensitive = true" in tf
    assert "aws_secretsmanager_secret_version" in tf
    # Removing it from HEAD is not the fix; rotating it is.
    assert "Rotate" in tf
