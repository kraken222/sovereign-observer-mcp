# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/checkov_scanner.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""Checkov-powered Terraform/IaC scanner.

This is the engine behind ``POST /api/iac/scan-pr``. It takes the raw ``.tf``
sources a CI job collected, runs Checkov against them, and normalises every
failed check into the finding shape the PR endpoint already speaks
(``file``/``line``/``severity``/``resource_address``/``remediation_*``).

Why Checkov rather than our own policy engine for IaC:
  * 1000+ maintained Terraform policies (CKV_AWS_/CKV_AZURE_/CKV_GCP_*).
  * Findings arrive already anchored to a precise ``file_line_range`` — Checkov
    parses the HCL itself, so we do not need the plan JSON or a separate line
    locator for the IaC path.
  * Apache-2.0, runs fully offline with ``--skip-download``.

Design choices:
  * We shell out to ``python -m checkov.main`` in a temp dir rather than calling
    the Runner API in-process. Checkov mutates a lot of global/registry state on
    import; isolating it in a subprocess keeps the Flask worker clean and makes
    the scan trivially killable on timeout.
  * Checkov's community edition reports ``severity: null`` for most checks
    (severities live behind the paid Prisma API). We derive a deterministic
    severity from a curated check-id map plus a keyword fallback so the merge
    gate (``fail_on``) behaves predictably.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Severity buckets in the capitalised form the PR endpoint/markdown expect.
_CRITICAL = "Critical"
_HIGH = "High"
_MEDIUM = "Medium"
_LOW = "Low"
_INFO = "Info"

# ── curated severity overrides for well-known, demo-relevant checks ──────────
# Anything not listed falls through to the keyword classifier below. The intent
# is that genuinely dangerous misconfigs (open to the internet, unencrypted,
# publicly reachable data stores) land at High/Critical so the gate trips.
_SEVERITY_BY_CHECK_ID: Dict[str, str] = {
    # — network exposure —
    "CKV_AWS_24": _CRITICAL,   # SG ingress 0.0.0.0/0 -> 22 (SSH)
    "CKV_AWS_25": _CRITICAL,   # SG ingress 0.0.0.0/0 -> 3389 (RDP)
    "CKV_AWS_260": _CRITICAL,  # SG ingress 0.0.0.0/0 -> 80
    "CKV_AWS_277": _CRITICAL,  # SG no description / wide open egress variants
    # — public data stores —
    "CKV_AWS_17": _CRITICAL,   # RDS publicly accessible
    "CKV_AWS_53": _HIGH,       # S3 block public ACLs
    "CKV_AWS_54": _HIGH,       # S3 block public policy
    "CKV_AWS_55": _HIGH,       # S3 ignore public ACLs
    "CKV_AWS_56": _HIGH,       # S3 restrict public buckets
    "CKV2_AWS_6": _HIGH,       # S3 bucket has a public access block
    "CKV2_AWS_61": _LOW,       # S3 lifecycle
    "CKV2_AWS_62": _LOW,       # S3 event notifications
    # — encryption at rest / in transit —
    "CKV_AWS_16": _HIGH,       # RDS storage encrypted
    "CKV_AWS_145": _MEDIUM,    # S3 KMS encryption
    "CKV_AWS_21": _MEDIUM,     # S3 versioning
    "CKV_AWS_18": _MEDIUM,     # S3 access logging
    # — RDS hardening —
    "CKV_AWS_157": _MEDIUM,    # RDS Multi-AZ
    "CKV_AWS_293": _MEDIUM,    # RDS deletion protection
    "CKV_AWS_161": _MEDIUM,    # RDS IAM auth
    "CKV_AWS_129": _LOW,       # RDS logging
    "CKV_AWS_118": _LOW,       # RDS enhanced monitoring
    "CKV_AWS_226": _LOW,       # RDS minor upgrades
    # — hygiene —
    "CKV_AWS_23": _LOW,        # SG/rule description
    "CKV2_AWS_5": _LOW,        # SG attached to a resource
    "CKV_AWS_144": _LOW,       # S3 cross-region replication
    # — secrets in source (see _SECRET_ATTRIBUTES) —
    "SOV_SECRET_1": _CRITICAL, # credential written as a literal in the HCL
}

# Keyword → severity, applied to the check name when no curated id match exists.
# Ordered most-severe first; first hit wins.
_KEYWORD_SEVERITY = [
    (_CRITICAL, ("public", "publicly", "0.0.0.0", "internet", "anonymous")),
    (_HIGH, ("encrypt", "encryption", "kms", "unencrypted", "tls", "ssl", "secret")),
    (_MEDIUM, ("logging", "log ", "monitor", "versioning", "backup", "mfa",
               "deletion protection", "multi-az", "rotation", "audit")),
]

# Map a Terraform resource-type prefix to a human service label.
_SERVICE_BY_PREFIX = [
    ("aws_s3", "S3"),
    ("aws_db_instance", "RDS"),
    ("aws_rds", "RDS"),
    ("aws_security_group", "EC2"),
    ("aws_vpc_security_group", "EC2"),
    ("aws_instance", "EC2"),
    ("aws_ebs", "EC2"),
    ("aws_iam", "IAM"),
    ("aws_lambda", "Lambda"),
    ("aws_kms", "KMS"),
    ("aws_cloudtrail", "CloudTrail"),
    ("aws_eks", "EKS"),
    ("azurerm_storage", "Storage"),
    ("azurerm_key_vault", "KeyVault"),
    ("azurerm_sql", "SQL"),
    ("azurerm_mssql", "SQL"),
    ("azurerm_postgresql", "PostgreSQL"),
    ("azurerm_virtual_machine", "Compute"),
    ("azurerm_linux_virtual_machine", "Compute"),
    ("google_storage", "Storage"),
    ("google_sql", "SQL"),
    ("google_compute", "Compute"),
    ("google_container", "GKE"),
]

# ── curated, paste-ready Terraform fixes for the highest-value checks ────────
# This is the "suggest a PR" payload. {res} is interpolated with the failing
# resource's local name so the snippet drops in cleanly.
_TERRAFORM_FIX_BY_CHECK_ID: Dict[str, Dict[str, str]] = {
    "CKV_AWS_53": {
        "summary": "Enable block_public_acls on the S3 public access block.",
        "terraform": 'block_public_acls = true  # add inside aws_s3_bucket_public_access_block.{res}',
    },
    "CKV_AWS_54": {
        "summary": "Enable block_public_policy on the S3 public access block.",
        "terraform": 'block_public_policy = true  # add inside aws_s3_bucket_public_access_block.{res}',
    },
    "CKV_AWS_55": {
        "summary": "Enable ignore_public_acls on the S3 public access block.",
        "terraform": 'ignore_public_acls = true  # add inside aws_s3_bucket_public_access_block.{res}',
    },
    "CKV_AWS_56": {
        "summary": "Enable restrict_public_buckets on the S3 public access block.",
        "terraform": 'restrict_public_buckets = true  # add inside aws_s3_bucket_public_access_block.{res}',
    },
    "CKV2_AWS_6": {
        "summary": "Attach a public access block that locks the bucket down.",
        "terraform": (
            'resource "aws_s3_bucket_public_access_block" "{res}" {{\n'
            '  bucket                  = aws_s3_bucket.{res}.id\n'
            '  block_public_acls       = true\n'
            '  block_public_policy     = true\n'
            '  ignore_public_acls      = true\n'
            '  restrict_public_buckets = true\n'
            '}}'
        ),
    },
    "CKV_AWS_21": {
        "summary": "Enable versioning on the S3 bucket.",
        "terraform": (
            'resource "aws_s3_bucket_versioning" "{res}" {{\n'
            '  bucket = aws_s3_bucket.{res}.id\n'
            '  versioning_configuration {{\n'
            '    status = "Enabled"\n'
            '  }}\n'
            '}}'
        ),
    },
    "CKV_AWS_145": {
        "summary": "Encrypt the S3 bucket with a KMS key by default.",
        "terraform": (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "{res}" {{\n'
            '  bucket = aws_s3_bucket.{res}.id\n'
            '  rule {{\n'
            '    apply_server_side_encryption_by_default {{\n'
            '      sse_algorithm = "aws:kms"\n'
            '    }}\n'
            '  }}\n'
            '}}'
        ),
    },
    "CKV_AWS_18": {
        "summary": "Enable S3 access logging to an audit bucket.",
        "terraform": (
            'resource "aws_s3_bucket_logging" "{res}" {{\n'
            '  bucket        = aws_s3_bucket.{res}.id\n'
            '  target_bucket = aws_s3_bucket.log_bucket.id\n'
            '  target_prefix = "log/"\n'
            '}}'
        ),
    },
    "CKV_AWS_24": {
        "summary": "Remove the 0.0.0.0/0 ingress on port 22; scope SSH to known CIDRs.",
        "terraform": (
            'ingress {{\n'
            '  from_port   = 22\n'
            '  to_port     = 22\n'
            '  protocol    = "tcp"\n'
            '  cidr_blocks = ["10.0.0.0/8"]  # replace with your admin CIDR\n'
            '}}'
        ),
    },
    "CKV_AWS_16": {
        "summary": "Enable storage encryption at rest on the RDS instance.",
        "terraform": "storage_encrypted = true  # add inside aws_db_instance.{res}",
    },
    "CKV_AWS_17": {
        "summary": "Make the RDS instance private (not publicly accessible).",
        "terraform": "publicly_accessible = false  # set inside aws_db_instance.{res}",
    },
    "CKV_AWS_293": {
        "summary": "Enable deletion protection on the RDS instance.",
        "terraform": "deletion_protection = true  # add inside aws_db_instance.{res}",
    },
    "CKV_AWS_157": {
        "summary": "Enable Multi-AZ on the RDS instance for resilience.",
        "terraform": "multi_az = true  # add inside aws_db_instance.{res}",
    },
    "CKV_AWS_161": {
        "summary": "Enable IAM database authentication on the RDS instance.",
        "terraform": "iam_database_authentication_enabled = true  # add inside aws_db_instance.{res}",
    },
    "CKV_AWS_129": {
        "summary": "Export RDS logs to CloudWatch for retention and alerting.",
        "terraform": 'enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]  # add inside aws_db_instance.{res}',
    },
    "CKV_AWS_118": {
        "summary": "Enable enhanced monitoring on the RDS instance.",
        "terraform": (
            'monitoring_interval = 60                               # add inside aws_db_instance.{res}\n'
            'monitoring_role_arn = aws_iam_role.rds_monitoring.arn  # role w/ AmazonRDSEnhancedMonitoringRole'
        ),
    },
    "CKV_AWS_353": {
        "summary": "Enable Performance Insights on the RDS instance.",
        "terraform": "performance_insights_enabled = true  # add inside aws_db_instance.{res}",
    },
    "CKV_AWS_226": {
        "summary": "Apply minor engine upgrades automatically.",
        "terraform": "auto_minor_version_upgrade = true  # add inside aws_db_instance.{res}",
    },
    "CKV2_AWS_60": {
        "summary": "Copy resource tags onto RDS snapshots.",
        "terraform": "copy_tags_to_snapshot = true  # add inside aws_db_instance.{res}",
    },
    "CKV_AWS_23": {
        "summary": "Add a description to every security-group rule.",
        "terraform": 'description = "scoped access for <purpose>"  # add to each ingress/egress block in {res}',
    },
    "CKV2_AWS_61": {
        "summary": "Attach a lifecycle configuration to expire old object versions.",
        "terraform": (
            'resource "aws_s3_bucket_lifecycle_configuration" "{res}" {{\n'
            '  bucket = aws_s3_bucket.{res}.id\n'
            '  rule {{\n'
            '    id     = "expire-noncurrent"\n'
            '    status = "Enabled"\n'
            '    noncurrent_version_expiration {{ noncurrent_days = 90 }}\n'
            '  }}\n'
            '}}'
        ),
    },
    "CKV2_AWS_62": {
        "summary": "Enable S3 event notifications (e.g. to SNS/SQS/Lambda).",
        "terraform": (
            'resource "aws_s3_bucket_notification" "{res}" {{\n'
            '  bucket = aws_s3_bucket.{res}.id\n'
            '  topic {{\n'
            '    topic_arn = aws_sns_topic.s3_events.arn\n'
            '    events    = ["s3:ObjectCreated:*"]\n'
            '  }}\n'
            '}}'
        ),
    },
    "SOV_SECRET_1": {
        "summary": (
            "Move the credential out of the Terraform source and rotate it — "
            "it is in version control and must be treated as compromised."
        ),
        "terraform": (
            '# 1. Declare it as a sensitive variable and supply the value at plan\n'
            '#    time (TF_VAR_*, a gitignored tfvars file, or your CI secret store)\n'
            '#    -- never as a default.\n'
            'variable "{res}_password" {{\n'
            '  type      = string\n'
            '  sensitive = true\n'
            '}}\n'
            '\n'
            '#    password = var.{res}_password\n'
            '\n'
            '# 2. Or read it from a secret manager so no human handles the value:\n'
            'data "aws_secretsmanager_secret_version" "{res}" {{\n'
            '  secret_id = "prod/{res}/password"\n'
            '}}\n'
            '\n'
            '#    password = data.aws_secretsmanager_secret_version.{res}.secret_string\n'
            '\n'
            '# 3. Rotate the exposed credential. Deleting it from HEAD does not delete\n'
            '#    it from the history of every clone that already pulled it.'
        ),
    },
}


# Checks whose fix is a safe, in-place, single-attribute change — the only ones
# eligible for opt-in auto-apply. "Add a whole new resource" fixes (versioning,
# public-access blocks, encryption configs) are deliberately NOT here; they stay
# advisory because applying them mechanically is riskier.
#
# Every entry is hand-verified against the Checkov check's SOURCE, not against
# its registry metadata. `get_expected_value()` returns a base-class default of
# True for checks that never set one, which makes bulk-importing the registry
# actively dangerous: it reports `azurerm_linux_web_app identity = true` (a
# block, so that is invalid HCL) and `azurerm_storage_account
# allow_nested_items_to_be_public = true` (the insecure direction). See
# test_autofix_allowlist.py, which encodes that trap so nobody automates this.
_AUTO_FIXABLE_CHECKS = {
    "CKV_AWS_16",   # storage_encrypted = true
    "CKV_AWS_17",   # publicly_accessible = false
    "CKV_AWS_293",  # deletion_protection = true
    "CKV_AWS_157",  # multi_az = true
    "CKV_AWS_161",  # iam_database_authentication_enabled = true
    "CKV_AWS_226",  # auto_minor_version_upgrade = true
    "CKV_AWS_7",    # enable_key_rotation = true
    "CKV_AZURE_91", # enable_non_ssl_port = false
    "CKV_AWS_126",  # monitoring = true (EC2 detailed monitoring)
}

# Syntactically clean, operationally dangerous — the distinction that keeps this
# list short. `backend/scripts/autofix_triage.py` proposed thirteen candidates
# that all pass every structural test: single flat attribute, explicit boolean
# expected value, no conditional logic. Twelve of them can take a running system
# down when applied inside a PR someone merges without reading:
#
#   public_network_access_enabled = false   cuts application connectivity to a
#     (CKV_AZURE_101/113/139/221/222/53/68/89)  database, registry or web app
#                                           unless a private endpoint already
#                                           exists
#   local_account_disabled = true           locks you out of an AKS cluster when
#     (CKV_AZURE_141)                       AAD integration is not configured
#   allow_extension_operations = false      breaks VM extensions, which is how
#     (CKV_AZURE_50)                        most monitoring agents install
#   enable_intranode_visibility = true      forces GKE node recreation
#     (CKV_GCP_61)
#   access_key_metadata_writes_enabled      breaks tooling that manages keys
#     (CKV_AZURE_132)
#
# These are still worth REPORTING as findings. They are not worth applying
# automatically. Reporting a risk and creating one are different products.
_AUTO_FIX_OPERATIONALLY_UNSAFE = {
    "public_network_access_enabled", "local_account_disabled",
    "allow_extension_operations", "enable_intranode_visibility",
    "access_key_metadata_writes_enabled", "local_user_enabled",
    "local_authentication_disabled",
}

# Deliberately NOT auto-fixable, with the reason, so nobody "completes the set"
# later without re-deriving why. These all look like single-attribute fixes and
# are not:
#
#   CKV_AWS_353  performance_insights_enabled — the check skips MariaDB/MySQL on
#                small instance classes, where AWS rejects the setting outright.
#                Applying it blind produces a plan that will not apply.
#   CKV_AZURE_3  enable_https_traffic_only — renamed to https_traffic_only_enabled
#                in azurerm 4.x. A deterministic setter cannot know which
#                provider version the repo pins, so it could write a dead
#                attribute name.
#   CKV_AZURE_16 / CKV_GCP_20 / CKV_GCP_23 / CKV_GCP_26 / CKV_GCP_64
#                the "attribute" is a nested block; `identity = true` is not HCL.
#   CKV_AZURE_230 / CKV_GCP_79  the attribute is a string (sku_name,
#                database_version) with no single correct value.
_AUTO_FIX_REJECTED = {
    "CKV_AWS_353": "conditional on engine and instance class; AWS rejects it on small MySQL/MariaDB",
    "CKV_AZURE_3": "attribute renamed in azurerm 4.x; provider version is unknowable from the finding",
    "CKV_AZURE_16": "identity is a block, not a boolean attribute",
    "CKV_AZURE_230": "sku_name is a string with no single correct value",
    "CKV_GCP_79": "database_version is a string with no single correct value",
    "SOV_SECRET_1": "the fix removes a value rather than setting one; where the "
                    "secret should come from instead is a decision only the "
                    "owner can make, and the exposed value still needs rotating",
}

# The single attribute each auto-fixable check sets, expressed structurally so
# the GitHub Action can apply it deterministically (set-or-add the attribute
# inside the resource block) rather than parsing a snippet.
_AUTO_FIX_ATTRIBUTE = {
    "CKV_AWS_16":  ("storage_encrypted", "true"),
    "CKV_AWS_17":  ("publicly_accessible", "false"),
    "CKV_AWS_293": ("deletion_protection", "true"),
    "CKV_AWS_157": ("multi_az", "true"),
    "CKV_AWS_161": ("iam_database_authentication_enabled", "true"),
    "CKV_AWS_226": ("auto_minor_version_upgrade", "true"),
    # Safe *because* we only fix findings that FAILED. CKV_AWS_7 returns UNKNOWN
    # for asymmetric keys, which auto-rotation does not support — so a FAIL is
    # already proof the key is symmetric and the attribute applies.
    "CKV_AWS_7":   ("enable_key_rotation", "true"),
    # The check sets get_expected_value() -> False explicitly; this is one of the
    # few where the registry value can be trusted, and it was still read from
    # source to confirm.
    "CKV_AZURE_91": ("enable_non_ssl_port", "false"),
    # Purely additive: turns on EC2 detailed monitoring. Costs a little money,
    # breaks nothing, removes no access path.
    "CKV_AWS_126": ("monitoring", "true"),
}

# Meta-arguments that make a resource's config dynamic. Checkov resolves these
# poorly (false positives on nested dynamic blocks — e.g. AWS WAF rules), so a
# mechanical fix could break a working setup. Any resource using one of these is
# forced to advisory-only, never auto-applied.
_META_LOOP_PATTERNS = (
    re.compile(r'(?m)^\s*dynamic\s+"'),
    re.compile(r'(?m)^\s*count\s*='),
    re.compile(r'(?m)^\s*for_each\s*='),
)


# ── hard coded credentials in the HCL itself ─────────────────────────────────
# Checkov does not catch these. Its `terraform` framework has no check for a
# literal in a credential attribute, and its `secrets` framework is
# entropy-based, so it walks straight past `password = "hunter2"` — verified
# against checkov 3.3.11. That is the single most obvious thing in a bad .tf
# file and the one an LLM reviewer always flags, so its absence read as the
# scanner being unserious.
#
# Exact attribute names, never substrings. `secret_id`, `secret_arn`,
# `key_name` and friends *reference* a secret rather than containing one, and a
# substring match would flag every one of them. A security check that cries
# wolf gets muted, and then it catches nothing at all.
#
# `connection_string` is deliberately absent: it frequently holds only an
# endpoint, and this list is worth more narrow than broad.
_SECRET_ATTRIBUTES = frozenset({
    "password",
    "master_password",
    "admin_password",
    "administrator_login_password",
    "root_password",
    "db_password",
    "passphrase",
    "secret",
    "client_secret",
    "secret_key",
    "secret_access_key",
    "access_key",
    "api_key",
    "auth_token",
    "token",
    "private_key",
    "secret_string",
    "shared_access_key",
})

# `attr = "literal"` on one line, and nothing else. Anything computed —
# `var.db_password`, `file(...)`, `jsonencode(...)`, a heredoc, a list — fails
# to match, which is what keeps the false-positive rate at zero. A commented
# line cannot match either: the attribute name has to start the line.
_SECRET_ASSIGNMENT = re.compile(
    r'^\s*(?P<attr>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(?P<value>[^"]*)"\s*(?:[#/].*)?$'
)

# Block headers we can name a finding after: `resource "aws_db_instance" "prod"`
# -> aws_db_instance.prod, `provider "aws"` -> provider.aws.
_BLOCK_HEADER = re.compile(
    r'^\s*(?P<kind>resource|data|provider|module|variable|output)\s+(?P<labels>[^{]*)\{'
)
_QUOTED_LABEL = re.compile(r'"([^"]*)"')

# Strip string contents before counting braces, so a `{` inside a value does not
# throw the block tracker off.
_HCL_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')

SECRET_CHECK_ID = "SOV_SECRET_1"
SECRET_CHECK_NAME = "Ensure no credential is hard coded in Terraform source"


class CheckovScanError(RuntimeError):
    """Raised when Checkov cannot be invoked or returns unparseable output."""


class CheckovScanner:
    """Run Checkov against in-memory Terraform sources and normalise findings."""

    DEFAULT_TIMEOUT = 180

    @staticmethod
    def is_available() -> bool:
        """True when the checkov package can be imported in this interpreter."""
        try:
            import checkov  # noqa: F401
            return True
        except Exception:
            return False

    @classmethod
    def scan(
        cls,
        tf_sources: Dict[str, str],
        changed_files: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> List[dict]:
        """Scan ``relpath -> .tf contents`` and return the list of findings.

        Thin wrapper over :meth:`analyze` for callers that only need findings.
        """
        return cls.analyze(tf_sources, changed_files=changed_files, timeout=timeout)["findings"]

    @classmethod
    def analyze(
        cls,
        tf_sources: Dict[str, str],
        changed_files: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> dict:
        """Scan a mapping of ``relpath -> .tf contents``.

        Returns ``{"findings": [...], "summary": {...}, "provider": str}``.

        Each finding dict carries: id, check_id, title, severity, service,
        resource, resource_address, file, line, evidence, cis_control,
        remediation_summary, remediation_terraform, remediation_docs,
        auto_capable. ``file`` paths are repo-root-relative with forward
        slashes so they line up with the GitHub PR diff.
        """
        if not tf_sources:
            return {"findings": [], "summary": {"passed": 0, "failed": 0, "resource_count": 0}, "provider": "aws"}

        raw = cls._run_checkov_dir(tf_sources, timeout=timeout or cls.DEFAULT_TIMEOUT)
        return cls._build_result(raw, changed_files=changed_files, anchor_lines=True,
                                 sources=tf_sources, allow_auto_fix=True)

    @classmethod
    def analyze_plan(
        cls,
        plan_json: dict,
        timeout: Optional[int] = None,
    ) -> dict:
        """Scan a Terraform *plan JSON* with Checkov (``checkov -f plan.json``).

        Used by the in-app IaC scan, which receives a plan rather than raw
        sources. Plan JSON has no HCL source locations, so findings come back
        without a usable ``file``/``line`` (we null them) — but the dashboard
        keys on control + resource, not on a line, so that is fine.

        Returns the same ``{"findings", "summary", "provider"}`` shape as
        :meth:`analyze`.
        """
        if not isinstance(plan_json, dict) or not plan_json:
            return {"findings": [], "summary": {"passed": 0, "failed": 0, "resource_count": 0}, "provider": "aws"}

        raw = cls._run_checkov_plan(plan_json, timeout=timeout or cls.DEFAULT_TIMEOUT)
        # Plan-based scans feed the dashboard, not the PR auto-fix flow, so
        # auto-apply is off here (no sources to verify against).
        return cls._build_result(raw, changed_files=None, anchor_lines=False,
                                 sources=None, allow_auto_fix=False)

    @classmethod
    def _build_result(cls, raw, changed_files, anchor_lines: bool,
                      sources: Optional[Dict[str, str]] = None,
                      allow_auto_fix: bool = False) -> dict:
        failed = cls._extract_failed_checks(raw)
        summary = cls._extract_summary(raw)
        changed_set = {cls._norm_path(p) for p in (changed_files or [])}
        findings: List[dict] = []
        for chk in failed:
            item = cls._normalise(chk, anchor_lines=anchor_lines)
            if item is None:
                continue
            item["in_changed_file"] = (item.get("file") in changed_set) if changed_set else None
            cls._set_auto_fixable(item, sources, allow_auto_fix)
            findings.append(item)

        # Checkov has no policy for a credential written straight into the HCL,
        # so this pass runs alongside it rather than through it. Source-only:
        # plan JSON has the values resolved and no line to anchor to.
        secrets = cls._scan_hardcoded_secrets(sources)
        for item in secrets:
            item["in_changed_file"] = (
                (item.get("file") in changed_set) if changed_set else None
            )
        findings.extend(secrets)
        if secrets:
            summary["failed"] = (summary.get("failed") or 0) + len(secrets)

        provider = cls._detect_provider(failed) or "aws"
        return {"findings": findings, "summary": summary, "provider": provider}

    @classmethod
    def _set_auto_fixable(cls, item: dict, sources: Optional[Dict[str, str]],
                          allow_auto_fix: bool) -> None:
        """Decide whether a finding's fix may be auto-applied (opt-in) vs stays
        advisory. A fix is auto-applyable only when ALL hold:
          * auto-apply is allowed for this scan (PR/source flow), and
          * the check is on the in-place single-attribute allowlist, and
          * a concrete Terraform fix exists, and
          * the resource does NOT use dynamic/count/for_each (which Checkov
            mis-evaluates — applying a fix there could break a working config).
        """
        check_id = item.get("check_id")
        eligible = (
            allow_auto_fix
            and check_id in _AUTO_FIXABLE_CHECKS
            and bool(item.get("remediation_terraform"))
        )
        if eligible and sources and cls._resource_uses_meta_loops(sources, item.get("resource_address")):
            item["auto_fixable"] = False
            item["auto_fix_blocked_reason"] = (
                "resource uses dynamic/count/for_each — fix kept advisory to "
                "avoid breaking a working configuration"
            )
        else:
            item["auto_fixable"] = bool(eligible)

        # Attach the structured fix the Action applies (set-or-add attribute).
        if item["auto_fixable"] and check_id in _AUTO_FIX_ATTRIBUTE:
            attr, value = _AUTO_FIX_ATTRIBUTE[check_id]
            item["fix"] = {
                "file": item.get("file"),
                "resource_address": item.get("resource_address"),
                "attribute": attr,
                "value": value,
            }

    # ── hard coded credentials ────────────────────────────────────────────
    @classmethod
    def _scan_hardcoded_secrets(cls, sources: Optional[Dict[str, str]]) -> List[dict]:
        """Find credentials written as string literals in the HCL.

        Runs over the raw sources rather than Checkov's output because Checkov
        has no policy for this — see ``_SECRET_ATTRIBUTES``. Source-only, so
        plan-JSON scans (where ``sources`` is None) skip it: a plan has the
        values resolved and no file to point at.

        The finding never carries the secret itself. It reports the attribute
        and the line, which is enough to find it and does not copy it into a
        scan record, a PR comment, or an assistant's context window.
        """
        findings: List[dict] = []
        for path, content in (sources or {}).items():
            if not isinstance(content, str):
                continue
            file_path = cls._norm_path(path)
            for line_no, attr, address in cls._iter_secret_assignments(content):
                local_name = cls._local_name(address)
                item = {
                    "id": SECRET_CHECK_ID,
                    "check_id": SECRET_CHECK_ID,
                    "title": SECRET_CHECK_NAME,
                    "severity": cls._severity_for(SECRET_CHECK_ID, SECRET_CHECK_NAME, None),
                    "service": cls._service_for(address) if "." in address else "IaC",
                    "resource": address,
                    "resource_address": address,
                    "evidence": (
                        f"{SECRET_CHECK_ID}: attribute \"{attr}\" is assigned a literal "
                        f"value — {address or file_path}"
                    ),
                    "cis_control": None,
                    "file": file_path or None,
                    "line": line_no,
                    "line_match": "attribute",
                    "remediation_docs": None,
                    "auto_capable": False,
                    # Never mechanically applied: the fix removes a value rather
                    # than setting one, and only the owner knows where the value
                    # should come from instead.
                    "auto_fixable": False,
                    "secret_attribute": attr,
                }
                cls._attach_remediation(
                    item, SECRET_CHECK_ID, SECRET_CHECK_NAME, local_name, item["service"]
                )
                findings.append(item)
        return findings

    @classmethod
    def _iter_secret_assignments(cls, content: str):
        """Yield ``(line_number, attribute, resource_address)`` per literal."""
        address = ""
        depth = 0
        for idx, raw_line in enumerate(content.splitlines(), start=1):
            stripped = _HCL_STRING.sub('""', raw_line)

            if depth == 0:
                header = _BLOCK_HEADER.match(raw_line)
                if header:
                    address = cls._address_from_header(header)

            match = _SECRET_ASSIGNMENT.match(raw_line)
            if match:
                attr = match.group("attr").lower()
                value = match.group("value")
                # An empty string is a placeholder, not a credential, and
                # "${...}" is a reference that happens to be quoted.
                if attr in _SECRET_ATTRIBUTES and value and "${" not in value:
                    yield idx, attr, address

            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                depth = 0
                address = ""

    @staticmethod
    def _address_from_header(header) -> str:
        """`resource "aws_db_instance" "prod"` -> ``aws_db_instance.prod``."""
        kind = header.group("kind")
        labels = _QUOTED_LABEL.findall(header.group("labels") or "")
        if not labels:
            return kind
        if kind == "resource":
            return ".".join(labels)
        return ".".join([kind, *labels])

    # ── dynamic / count / for_each detection ───────────────────────────────
    @classmethod
    def _resource_uses_meta_loops(cls, sources: Dict[str, str], address: Optional[str]) -> bool:
        """True if the resource block for ``address`` contains a dynamic block,
        ``count``, or ``for_each`` in any of the supplied .tf sources."""
        rtype, rname = cls._addr_type_name(address)
        if not rtype or not rname:
            return False
        decl = re.compile(
            r'^\s*resource\s+"%s"\s+"%s"\s*\{' % (re.escape(rtype), re.escape(rname))
        )
        for content in (sources or {}).values():
            if not isinstance(content, str):
                continue
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if decl.match(line):
                    block = cls._extract_block(lines, i)
                    if any(p.search(block) for p in _META_LOOP_PATTERNS):
                        return True
        return False

    @staticmethod
    def _extract_block(lines: List[str], start: int) -> str:
        """Return the text of an HCL block starting at ``start`` by brace-matching.

        Intentionally a simple brace counter (over-extending is safe — it only
        makes the dynamic-block check more cautious, never less)."""
        depth = 0
        started = False
        out: List[str] = []
        for line in lines[start:]:
            out.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
        return "\n".join(out)

    @staticmethod
    def _addr_type_name(address: Optional[str]):
        """``aws_db_instance.prod`` -> ('aws_db_instance', 'prod');
        strips module prefixes and ``[idx]`` suffixes."""
        if not address or not isinstance(address, str):
            return None, None
        clean = re.sub(r'\[[^\]]*\]', '', address)
        parts = [p for p in clean.split(".") if p]
        if len(parts) < 2:
            return None, None
        return parts[-2], parts[-1]

    @classmethod
    def _extract_summary(cls, raw) -> dict:
        blocks = raw if isinstance(raw, list) else [raw]
        passed = failed = resources = 0
        for block in blocks:
            if not isinstance(block, dict):
                continue
            ct = block.get("check_type")
            if ct and ct not in cls._TF_CHECK_TYPES:
                continue
            s = block.get("summary") or {}
            passed += int(s.get("passed") or 0)
            failed += int(s.get("failed") or 0)
            resources = max(resources, int(s.get("resource_count") or 0))
        return {"passed": passed, "failed": failed, "resource_count": resources}

    @staticmethod
    def _detect_provider(failed_checks: List[dict]) -> Optional[str]:
        """Infer aws/azure/gcp from the resource types of the failed checks."""
        votes = {"aws": 0, "azure": 0, "gcp": 0}
        for chk in failed_checks:
            rtype = (chk.get("resource") or "").split(".")[0]
            cid = (chk.get("check_id") or "").upper()
            if rtype.startswith("aws_") or "_AWS_" in cid:
                votes["aws"] += 1
            elif rtype.startswith("azurerm_") or "_AZURE_" in cid:
                votes["azure"] += 1
            elif rtype.startswith("google_") or "_GCP_" in cid:
                votes["gcp"] += 1
        best = max(votes, key=votes.get)
        return best if votes[best] > 0 else None

    # ── checkov invocation ────────────────────────────────────────────────
    @classmethod
    def _run_checkov_dir(cls, tf_sources: Dict[str, str], timeout: int) -> dict:
        """Run Checkov over raw .tf sources written to a temp directory."""
        with tempfile.TemporaryDirectory(prefix="sovereign_ckv_") as scan_dir:
            cls._materialise_sources(scan_dir, tf_sources)
            cmd = [
                sys.executable, "-m", "checkov.main",
                "-d", scan_dir,
                "-o", "json", "--compact", "--quiet",
                "--framework", "terraform",
                "--skip-download",
            ]
            return cls._invoke(cmd, cwd=scan_dir, timeout=timeout)

    @classmethod
    def _run_checkov_plan(cls, plan_json: dict, timeout: int) -> dict:
        """Run Checkov over a Terraform plan JSON file (``checkov -f``)."""
        with tempfile.TemporaryDirectory(prefix="sovereign_ckvp_") as scan_dir:
            plan_path = os.path.join(scan_dir, "tfplan.json")
            with open(plan_path, "w", encoding="utf-8") as fh:
                json.dump(plan_json, fh)
            cmd = [
                sys.executable, "-m", "checkov.main",
                "-f", plan_path,
                "-o", "json", "--compact", "--quiet",
                "--framework", "terraform_plan",
                "--skip-download",
            ]
            return cls._invoke(cmd, cwd=scan_dir, timeout=timeout)

    @staticmethod
    def _invoke(cmd: list, cwd: str, timeout: int) -> dict:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
            )
        except FileNotFoundError as e:
            raise CheckovScanError(f"checkov executable not found: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise CheckovScanError(f"checkov timed out after {timeout}s") from e

        # Checkov exits 1 when it finds failures — that is success for us.
        # A truly broken run prints nothing parseable to stdout.
        stdout = (proc.stdout or "").strip()
        if not stdout:
            raise CheckovScanError(
                f"checkov produced no JSON (exit {proc.returncode}): "
                f"{(proc.stderr or '')[:500]}"
            )
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            raise CheckovScanError(f"could not parse checkov JSON: {e}") from e

    @staticmethod
    def _materialise_sources(scan_dir: str, tf_sources: Dict[str, str]) -> None:
        """Write each source to ``scan_dir`` preserving its relative path so
        Checkov's reported ``file_path`` matches the repo layout."""
        for rel, content in tf_sources.items():
            if not isinstance(content, str):
                continue
            safe_rel = rel.replace("\\", "/").lstrip("/")
            # Guard against path traversal in attacker-controlled keys.
            parts = [p for p in safe_rel.split("/") if p not in ("", ".", "..")]
            if not parts:
                continue
            dest = os.path.join(scan_dir, *parts)
            os.makedirs(os.path.dirname(dest) or scan_dir, exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(content)

    # Check types we accept (raw .tf scans and plan-JSON scans).
    _TF_CHECK_TYPES = ("terraform", "terraform_plan")

    @classmethod
    def _extract_failed_checks(cls, raw) -> List[dict]:
        """Pull failed_checks out of Checkov's output (dict or list form)."""
        blocks = raw if isinstance(raw, list) else [raw]
        failed: List[dict] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            ct = block.get("check_type")
            if ct and ct not in cls._TF_CHECK_TYPES:
                continue
            results = block.get("results") or {}
            failed.extend(results.get("failed_checks") or [])
        return failed

    # ── normalisation ─────────────────────────────────────────────────────
    @classmethod
    def _normalise(cls, chk: dict, anchor_lines: bool = True) -> Optional[dict]:
        check_id = chk.get("check_id") or chk.get("bc_check_id")
        if not check_id:
            return None
        name = chk.get("check_name") or check_id
        address = chk.get("resource") or ""
        # For plan-JSON scans the file/line point at the plan file, not the HCL,
        # so they are not useful — drop them.
        if anchor_lines:
            file_path = cls._norm_path(chk.get("file_path") or chk.get("file_abs_path") or "")
            line = cls._start_line(chk.get("file_line_range"))
        else:
            file_path = ""
            line = None
        severity = cls._severity_for(check_id, name, chk.get("severity"))
        service = cls._service_for(address)
        local_name = cls._local_name(address)

        item: dict = {
            "id": check_id,
            "check_id": check_id,
            "title": name,
            "severity": severity,
            "service": service,
            "resource": address,
            "resource_address": address,
            "evidence": f"{check_id}: {name} — {address}".strip(" —"),
            "cis_control": chk.get("bc_check_id"),
            "file": file_path or None,
            "line": line,
            "line_match": "resource" if line else None,
            "remediation_docs": chk.get("guideline"),
            "auto_capable": False,
        }

        cls._attach_remediation(item, check_id, name, local_name, service)
        return item

    @staticmethod
    def _norm_path(path: str) -> str:
        if not path:
            return ""
        p = str(path).replace("\\", "/").lstrip("/")
        if p.startswith("./"):
            p = p[2:]
        return p

    @staticmethod
    def _start_line(line_range) -> Optional[int]:
        if isinstance(line_range, (list, tuple)) and line_range:
            try:
                return int(line_range[0])
            except (TypeError, ValueError):
                return None
        return None

    @staticmethod
    def _local_name(address: str) -> str:
        # "aws_s3_bucket.data" -> "data"; "module.x.aws_s3_bucket.data[0]" -> "data"
        if not address:
            return "this"
        clean = address.split("[")[0]
        parts = [p for p in clean.split(".") if p]
        return parts[-1] if parts else "this"

    @classmethod
    def _service_for(cls, address: str) -> str:
        rtype = (address or "").split(".")[0]
        for prefix, label in _SERVICE_BY_PREFIX:
            if rtype.startswith(prefix):
                return label
        # Fall back to the provider token, e.g. "aws_foo_bar" -> "AWS"
        return rtype.split("_")[0].upper() if rtype else "IaC"

    @staticmethod
    def _severity_for(check_id: str, name: str, raw_severity) -> str:
        # 1) Honour an explicit severity if Checkov supplied one (paid edition).
        if isinstance(raw_severity, str) and raw_severity.strip():
            s = raw_severity.strip().capitalize()
            if s in (_CRITICAL, _HIGH, _MEDIUM, _LOW, _INFO):
                return s
        # 2) Curated override by check id.
        if check_id in _SEVERITY_BY_CHECK_ID:
            return _SEVERITY_BY_CHECK_ID[check_id]
        # 3) Keyword classifier on the check name.
        low = (name or "").lower()
        for sev, keywords in _KEYWORD_SEVERITY:
            if any(k in low for k in keywords):
                return sev
        return _LOW

    @classmethod
    def _attach_remediation(cls, item: dict, check_id: str, name: str,
                            local_name: str, service: str) -> None:
        """Attach a paste-ready Terraform fix + summary.

        Prefer a curated Checkov-specific snippet; otherwise fall back to the
        shared RemediationService playbook library (keyed by title keywords),
        and always keep the Checkov guideline URL as the doc link.
        """
        fix = _TERRAFORM_FIX_BY_CHECK_ID.get(check_id)
        if fix:
            item["remediation_summary"] = fix["summary"]
            item["remediation_terraform"] = fix["terraform"].format(res=local_name)
            return

        # Fallback: try the shared playbook library by the check name.
        try:
            from ..remediation_service import RemediationService
            pb = RemediationService.get_playbook(
                name,
                resource_id=local_name,
                provider="iac",
                control_id=check_id,
                resource_type=service,
            )
        except Exception:
            pb = None

        # Only adopt the shared playbook when it carries a concrete, pasteable
        # fix (Terraform or CLI). The library's generic fallback (console steps +
        # "no exact playbook available" prose) reads poorly inline, so for
        # unmapped checks we use Checkov's own imperative check name
        # ("Ensure the S3 bucket has access logging enabled") — it already
        # states the fix in one line.
        if pb and (pb.get("terraform") or pb.get("cli")):
            if pb.get("terraform"):
                item["remediation_terraform"] = pb["terraform"]
            if pb.get("cli"):
                item["remediation_cli"] = pb["cli"]
            if pb.get("steps"):
                item["remediation_steps"] = pb["steps"]
            if pb.get("docs") and not item.get("remediation_docs"):
                item["remediation_docs"] = pb["docs"]
            item["remediation_summary"] = pb.get("summary") or pb.get("title") or name
            item["auto_capable"] = bool(pb.get("auto_capable", False))
        else:
            item["remediation_summary"] = name
