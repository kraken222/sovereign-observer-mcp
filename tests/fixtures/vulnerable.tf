# Demo infrastructure for the Sovereign IaC PR scan.
# This file is INTENTIONALLY insecure — it triggers Critical + High findings
# so the merge gate fails on screen. Do not deploy.

provider "aws" {
  region = "us-east-1"
}

# ── S3 bucket with no public-access block → CKV2_AWS_6 (High) + hygiene checks
resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-exports"
}

# ── RDS: publicly reachable AND unencrypted → CKV_AWS_17 (Critical), CKV_AWS_16 (High)
resource "aws_db_instance" "prod" {
  identifier          = "acme-prod-db"
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  username            = "admin"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# ── Security group open to the world on SSH → CKV_AWS_24 (Critical)
resource "aws_security_group" "bastion" {
  name        = "acme-bastion"
  description = "bastion access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
