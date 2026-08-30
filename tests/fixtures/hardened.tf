# The "after" version — what the PR looks like once the suggested fixes are
# pasted in. Rename this over main.tf in the PR to show the check going green.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-exports"
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "prod" {
  identifier          = "acme-prod-db"
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  username            = "admin"
  publicly_accessible = false   # fixed: CKV_AWS_17
  storage_encrypted   = true    # fixed: CKV_AWS_16
  deletion_protection = true
  skip_final_snapshot = true
}

resource "aws_security_group" "bastion" {
  name        = "acme-bastion"
  description = "bastion access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]   # fixed: CKV_AWS_24 — scoped to internal CIDR
  }
}
