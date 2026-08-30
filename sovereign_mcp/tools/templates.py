"""``secure_template`` — the only genuinely preventive tool here.

Everything else in this package reacts: code exists, we find what is wrong with
it. This one stops the insecure code being written at all, which is a better
trade when the assistant is about to generate a resource from memory and the
provider's defaults are unsafe.

Every template below is verified by ``tests/test_templates.py``, which scans it
with the same engine ``scan_terraform`` uses and fails if any Critical or High
finding appears. So these are not "believed secure" — they are held secure by a
test that runs against the current policy set.

What the templates deliberately do NOT resolve are the findings that depend on
information only the user has: which bucket receives access logs, which region
replicates, how long the lifecycle policy retains. Inventing values for those
would produce Terraform that scans clean and is wrong. They are listed in
``notes`` instead, so the assistant can raise them with the user.
"""
from __future__ import annotations

from typing import Any, Dict, List

_TEMPLATES: Dict[str, Dict[str, Any]] = {}


def _register(
    resource_type: str,
    *,
    description: str,
    terraform: str,
    variables: List[str],
    notes: List[str],
    aliases: tuple = (),
) -> None:
    entry = {
        "resource_type": resource_type,
        "description": description,
        "terraform": terraform,
        "variables_required": variables,
        "notes": notes,
    }
    _TEMPLATES[resource_type] = entry
    for alias in aliases:
        _TEMPLATES[alias] = entry


_register(
    "aws_s3_bucket",
    description="S3 bucket: private, versioned, KMS-encrypted, public access blocked.",
    aliases=("s3", "aws_s3", "bucket"),
    variables=[],
    notes=[
        "Access logging (CKV_AWS_18) is not wired up — it needs a destination "
        "bucket that only you can name. Add aws_s3_bucket_logging pointing at "
        "your audit bucket.",
        "Cross-region replication and a lifecycle policy are left out for the "
        "same reason: both need decisions about region and retention.",
        "The KMS key policy grants the account root full key administration, "
        "which is AWS's documented baseline. Narrowing it is good practice but "
        "must not lock you out of your own key.",
    ],
    terraform='''resource "aws_s3_bucket" "example" {
  bucket = "example-bucket-name"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.example.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_kms_key" "example" {
  description             = "KMS key for the example bucket"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.example_kms.json
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "example_kms" {
  statement {
    sid       = "AllowAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}
''',
)


_register(
    "aws_db_instance",
    description="RDS instance: private, encrypted with a CMK, Multi-AZ, deletion-protected.",
    aliases=("rds", "aws_rds", "database"),
    variables=["db_username", "db_password", "rds_monitoring_role_arn"],
    notes=[
        "The password is referenced as a variable, not inlined. Source it from "
        "Secrets Manager or a tfvars file that is not committed.",
        "multi_az and Performance Insights both cost money. Turn them off "
        "knowingly if this is a non-production database — do not leave them on "
        "by accident.",
        "monitoring_role_arn expects an existing IAM role with the "
        "AmazonRDSEnhancedMonitoringRole policy attached.",
    ],
    terraform='''resource "aws_db_instance" "example" {
  identifier        = "example"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username = var.db_username
  password = var.db_password

  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.rds.arn
  publicly_accessible                 = false
  multi_az                            = true
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  backup_retention_period             = 7
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  monitoring_interval                 = 60
  monitoring_role_arn                 = var.rds_monitoring_role_arn
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.rds.arn
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "example-final"
}

resource "aws_kms_key" "rds" {
  description             = "KMS key for the example database"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.rds_kms.json
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "rds_kms" {
  statement {
    sid       = "AllowAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}
''',
)


_register(
    "aws_security_group",
    description="Security group: no 0.0.0.0/0 ingress, described rules, scoped egress.",
    aliases=("security_group", "sg", "firewall"),
    variables=["vpc_id", "load_balancer_security_group_id", "egress_cidr"],
    notes=[
        "Ingress references another security group rather than a CIDR. That is "
        "the pattern that survives contact with reality — CIDR allowlists drift "
        "as infrastructure moves.",
        "Uses the standalone aws_vpc_security_group_*_rule resources rather than "
        "inline ingress/egress blocks. Inline blocks are authoritative and will "
        "silently delete rules added elsewhere.",
        "If you need public ingress, terminate it at a load balancer with WAF in "
        "front, not on the instance security group.",
    ],
    terraform='''resource "aws_security_group" "example" {
  name        = "example-app"
  description = "Application tier: HTTPS from the load balancer only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id            = aws_security_group.example.id
  description                  = "HTTPS from the load balancer security group"
  referenced_security_group_id = var.load_balancer_security_group_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "https_out" {
  security_group_id = aws_security_group.example.id
  description       = "HTTPS to AWS service endpoints"
  cidr_ipv4         = var.egress_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
''',
)


_register(
    "azurerm_storage_account",
    description="Azure storage account: private endpoint only, CMK, TLS 1.2, no shared keys.",
    aliases=("azure_storage", "storage_account"),
    variables=["resource_group_name", "location", "key_vault_id", "key_vault_key_name"],
    notes=[
        "public_network_access_enabled = false means this is reachable only via "
        "a private endpoint or an explicit network rule. That is correct, and it "
        "will break anything expecting public access — wire the private endpoint "
        "before you apply.",
        "shared_access_key_enabled = false forces Entra ID auth. SDKs configured "
        "with a connection string will stop working; they need a credential.",
        "The customer-managed key expects an existing Key Vault key with purge "
        "protection enabled.",
    ],
    terraform='''resource "azurerm_storage_account" "example" {
  name                = "examplestorageacct"
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"

  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  infrastructure_encryption_enabled = true
  local_user_enabled                = false

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  identity {
    type = "SystemAssigned"
  }

  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }
}

resource "azurerm_storage_account_customer_managed_key" "example" {
  storage_account_id = azurerm_storage_account.example.id
  key_vault_id       = var.key_vault_id
  key_name           = var.key_vault_key_name
}
''',
)


_register(
    "google_storage_bucket",
    description="GCS bucket: uniform access, public access prevented, CMEK, versioned.",
    aliases=("gcs", "gcp_storage", "google_bucket"),
    variables=["log_bucket_name"],
    notes=[
        "prevent_destroy on the KMS key means Terraform will refuse to delete "
        "it. That is intentional — destroying the key makes every object "
        "encrypted with it permanently unreadable.",
        "The bucket's service agent needs roles/cloudkms.cryptoKeyEncrypterDecrypter "
        "on the key, or writes will fail at runtime rather than at plan time.",
        "location is set to the EU multi-region. Change it to match your data "
        "residency obligations before applying.",
    ],
    terraform='''resource "google_storage_bucket" "example" {
  name     = "example-bucket-name"
  location = "EU"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.example.id
  }

  logging {
    log_bucket = var.log_bucket_name
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_kms_key_ring" "example" {
  name     = "example-keyring"
  location = "europe-west1"
}

resource "google_kms_crypto_key" "example" {
  name            = "example-key"
  key_ring        = google_kms_key_ring.example.id
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}
''',
)


def available() -> List[str]:
    """Canonical resource types with a template (aliases excluded)."""
    seen = []
    for entry in _TEMPLATES.values():
        if entry["resource_type"] not in seen:
            seen.append(entry["resource_type"])
    return sorted(seen)


def get_template(resource_type: str) -> Dict[str, Any]:
    """Return a security-hardened starting point for ``resource_type``."""
    key = (resource_type or "").strip().lower()
    entry = _TEMPLATES.get(key)

    if entry is None:
        return {
            "error": f"No hardened template for '{resource_type}'.",
            "available": available(),
            "next_step": (
                "Write the resource as normal, then call scan_terraform on it. "
                "The scan covers far more resource types than these templates do."
            ),
        }

    out = dict(entry)
    out["verified"] = (
        "Scanned with the same engine as scan_terraform; contains no Critical or "
        "High findings. Enforced by tests/test_templates.py."
    )
    out["next_step"] = (
        "Replace the example names and variables with real values, then call "
        "scan_terraform on the result — substitutions can reintroduce findings."
    )
    return out
