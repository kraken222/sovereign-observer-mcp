"""``environment_aware`` seen from the assistant's side.

The behaviour that matters here is the default. An assistant that calls
``scan_terraform`` the ordinary way must get exactly what it got before this
feature existed — same severities, same order — because anything else means a
scanner quietly started reporting lower than the merge gate someone configured.
"""
from __future__ import annotations

from sovereign_mcp.tools.scan import run_scan

DEV = {
    "envs/dev/main.tf": (
        'resource "aws_db_instance" "scratch" {\n'
        '  identifier          = "scratch"\n'
        '  engine              = "postgres"\n'
        '  instance_class      = "db.t3.micro"\n'
        '  allocated_storage   = 20\n'
        '  storage_encrypted   = false\n'
        '  publicly_accessible = true\n'
        '}\n'
    )
}


def _by_check(result):
    return {f["check_id"]: f for f in result["findings"]}


def test_environment_is_reported_even_when_severity_is_untouched():
    result = run_scan(files=DEV)

    assert result["findings"], "expected findings on a deliberately bad fixture"
    assert {f["environment"] for f in result["findings"]} == {"development"}
    assert not any("severity_lowered_from" in f for f in result["findings"])


def test_the_default_call_changes_nothing_about_severity():
    """The property that keeps this from weakening anyone's pipeline."""
    plain = _by_check(run_scan(files=DEV))
    aware = _by_check(run_scan(files=DEV, environment_aware=True))

    assert plain["CKV_AWS_157"]["severity"] == "Medium"
    assert aware["CKV_AWS_157"]["severity"] == "Low"


def test_exposure_and_encryption_hold_their_severity_in_a_dev_stack():
    aware = _by_check(run_scan(files=DEV, environment_aware=True))

    assert aware["CKV_AWS_17"]["severity"] == "Critical"   # publicly accessible
    assert aware["CKV_AWS_16"]["severity"] == "High"       # unencrypted at rest
    assert "severity_lowered_from" not in aware["CKV_AWS_17"]
    assert "severity_lowered_from" not in aware["CKV_AWS_16"]


def test_a_lowered_finding_says_what_it_was():
    aware = _by_check(run_scan(files=DEV, environment_aware=True))

    assert aware["CKV_AWS_157"]["severity_lowered_from"] == "Medium"


def test_findings_stay_ordered_most_severe_first_after_re_ranking():
    result = run_scan(files=DEV, environment_aware=True)
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    severities = [rank[f["severity"]] for f in result["findings"]]

    assert severities == sorted(severities)


def test_an_unrecognised_path_leaves_everything_alone():
    sources = {"main.tf": DEV["envs/dev/main.tf"]}
    plain = _by_check(run_scan(files=sources))
    aware = _by_check(run_scan(files=sources, environment_aware=True))

    assert {f["environment"] for f in aware.values()} == {"unknown"}
    assert all(aware[c]["severity"] == plain[c]["severity"] for c in plain)
