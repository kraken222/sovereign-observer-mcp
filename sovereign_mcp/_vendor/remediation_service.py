# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/remediation_service.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""
Remediation Service — generates actionable remediation playbooks from findings.

This service does NOT auto-execute cloud CLI commands (security risk for SaaS).
Instead it produces structured remediation plans with:
  - Step-by-step instructions
  - Ready-to-paste CLI commands
  - Terraform/IaC fix snippets
  - Estimated effort and impact rating

Auto-remediation execution is intentionally gated behind user confirmation
and audit logging to satisfy SOC2 CC8.1 change management requirements.
"""
from datetime import datetime
import json
import logging

logger = logging.getLogger("RemediationService")

PROVIDER_DOCS = {
    'aws': 'https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html',
    'gcp': 'https://cloud.google.com/docs/security',
    'azure': 'https://learn.microsoft.com/en-us/azure/security/',
    'iac': 'https://developer.hashicorp.com/terraform/docs',
}

FRAMEWORK_DOCS = {
    'cis': 'https://www.cisecurity.org/cis-benchmarks',
    'soc2': 'https://www.aicpa-cima.com/resources/article/what-is-soc-2',
    'iso27001': 'https://www.iso.org/isoiec-27001-information-security.html',
    'nist': 'https://www.nist.gov/cyberframework',
}

RESOURCE_GUIDES = {
    'bucket': 'Review bucket access, encryption, versioning, and public exposure settings in the cloud console.',
    'iam': 'Review identity permissions, external principals, password policy, and MFA requirements.',
    'role': 'Review trust relationships, attached policies, and excessive permissions.',
    'security_group': 'Review inbound and outbound rules and remove overly broad network access.',
    'database': 'Review encryption, network exposure, backup, and authentication settings.',
    'lambda': 'Review function URL exposure, environment secrets, and execution role permissions.',
}

# ── Remediation playbooks keyed by check pattern ─────────────────────

PLAYBOOKS = {
    # ── S3 ──
    'Public Access': {
        'title': 'Block S3 Public Access',
        'impact': 'High',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to S3 Console → Select bucket → Permissions tab',
            'Enable "Block all public access" toggle',
            'Review and confirm the bucket policy does not grant Principal: "*"',
            'Verify ACL does not include "AllUsers" or "AuthenticatedUsers" grantees',
        ],
        'cli': 'aws s3api put-public-access-block --bucket {resource_id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true',
        'terraform': 'resource "aws_s3_bucket_public_access_block" "block" {{\n  bucket = "{resource_id}"\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}}',
        'rollback': 'aws s3api delete-public-access-block --bucket {resource_id}',
        'framework_refs': ['CIS 2.1.5', 'ISO A.13.1.1', 'SOC2 CC6.1'],
    },
    'Versioning': {
        'title': 'Enable S3 Bucket Versioning',
        'impact': 'Medium',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to S3 Console → Select bucket → Properties tab',
            'Enable Bucket Versioning',
            'Consider adding lifecycle rules to manage version costs',
        ],
        'cli': 'aws s3api put-bucket-versioning --bucket {resource_id} --versioning-configuration Status=Enabled',
        'terraform': 'resource "aws_s3_bucket_versioning" "versioning" {{\n  bucket = "{resource_id}"\n  versioning_configuration {{\n    status = "Enabled"\n  }}\n}}',
        'rollback': 'aws s3api put-bucket-versioning --bucket {resource_id} --versioning-configuration Status=Suspended',
        'framework_refs': ['CIS 2.1.3', 'ISO A.12.3.1', 'SOC2 A1.2'],
    },
    'Encryption': {
        'title': 'Enable S3 Server-Side Encryption',
        'impact': 'High',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to S3 Console → Select bucket → Properties tab',
            'Under Default encryption, enable SSE-S3 or SSE-KMS',
            'For sensitive data, use SSE-KMS with a Customer Managed Key (CMK)',
        ],
        'cli': 'aws s3api put-bucket-encryption --bucket {resource_id} --server-side-encryption-configuration \'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}\'',
        'terraform': 'resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {{\n  bucket = "{resource_id}"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "aws:kms"\n    }}\n  }}\n}}',
        'rollback': None,
        'framework_refs': ['CIS 2.1.1', 'ISO A.10.1.1', 'SOC2 CC6.1'],
    },
    # ── IAM ──
    'No MFA': {
        'title': 'Enable MFA for IAM User',
        'impact': 'Critical',
        'effort': 'Medium',
        'auto_capable': False,
        'steps': [
            'Navigate to IAM Console → Users → Select user',
            'Go to Security credentials tab',
            'Click "Assign MFA device"',
            'Choose virtual MFA (Authenticator app) or hardware token',
            'Scan QR code with authenticator app and enter two consecutive codes',
        ],
        'cli': 'aws iam enable-mfa-device --user-name {resource_id} --serial-number <mfa-device-arn> --authentication-code1 <code1> --authentication-code2 <code2>',
        'terraform': None,
        'rollback': None,
        'framework_refs': ['CIS 1.2', 'ISO A.9.4.2', 'SOC2 CC6.1'],
    },
    'Root Access Keys': {
        'title': 'Remove Root Account Access Keys',
        'impact': 'Critical',
        'effort': 'Low',
        'auto_capable': False,
        'steps': [
            'Sign in as root user → IAM Console → Security credentials',
            'Find active access keys and click "Make inactive" then "Delete"',
            'Create an IAM admin user with MFA as replacement',
            'Update any scripts using root keys to use the new IAM user',
        ],
        'cli': 'aws iam delete-access-key --access-key-id <key-id>  # Must run as root',
        'terraform': None,
        'rollback': None,
        'framework_refs': ['CIS 1.4', 'ISO A.9.2.6', 'SOC2 CC6.1'],
    },
    'Password Policy': {
        'title': 'Enforce Strong IAM Password Policy',
        'impact': 'High',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to IAM Console → Account settings',
            'Set minimum password length to 14+',
            'Require uppercase, lowercase, numbers, and symbols',
            'Set max password age to 90 days',
            'Enable password reuse prevention (24 passwords)',
        ],
        'cli': 'aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24',
        'terraform': 'resource "aws_iam_account_password_policy" "strict" {{\n  minimum_password_length        = 14\n  require_lowercase_characters   = true\n  require_numbers                = true\n  require_uppercase_characters   = true\n  require_symbols                = true\n  max_password_age               = 90\n  password_reuse_prevention      = 24\n}}',
        'rollback': None,
        'framework_refs': ['CIS 1.5', 'ISO A.9.4.3', 'SOC2 CC6.1'],
    },
    # ── EC2 / Network ──
    'Open to Internet': {
        'title': 'Restrict Security Group Ingress Rules',
        'impact': 'Critical',
        'effort': 'Medium',
        'auto_capable': True,
        'steps': [
            'Identify the security group in EC2 Console → Security Groups',
            'Review inbound rules with source 0.0.0.0/0',
            'Replace with specific CIDR blocks (office IPs, VPN ranges)',
            'For SSH (22) and RDP (3389) — restrict to known admin IPs only',
            'Test connectivity after changes',
        ],
        'cli': 'aws ec2 revoke-security-group-ingress --group-id {resource_id} --protocol tcp --port 22 --cidr 0.0.0.0/0',
        'terraform': None,
        'rollback': 'aws ec2 authorize-security-group-ingress --group-id {resource_id} --protocol tcp --port 22 --cidr 0.0.0.0/0',
        'framework_refs': ['CIS 4.1', 'ISO A.13.1.1', 'SOC2 CC6.6'],
    },
    'No VPC Flow Logs': {
        'title': 'Enable VPC Flow Logs',
        'impact': 'Medium',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to VPC Console → Select VPC',
            'Go to Flow Logs tab → Create flow log',
            'Set filter to "All" traffic',
            'Choose CloudWatch Logs or S3 as destination',
            'Create IAM role with permissions for the log destination',
        ],
        'cli': 'aws ec2 create-flow-logs --resource-ids {resource_id} --resource-type VPC --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /vpc/flow-logs/{resource_id}',
        'terraform': 'resource "aws_flow_log" "vpc" {{\n  vpc_id          = "{resource_id}"\n  traffic_type    = "ALL"\n  log_destination = aws_cloudwatch_log_group.flow.arn\n  iam_role_arn    = aws_iam_role.flow.arn\n}}',
        'rollback': None,
        'framework_refs': ['CIS 3.7', 'ISO A.12.4.1', 'SOC2 CC7.2'],
    },
    # ── Lambda ──
    'Public URL Access': {
        'title': 'Require Authentication on Lambda Function URL',
        'impact': 'Critical',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to Lambda Console → Select function',
            'Go to Configuration → Function URL',
            'Change Auth type from NONE to AWS_IAM',
            'Update calling applications with SigV4 signing',
        ],
        'cli': 'aws lambda update-function-url-config --function-name {resource_id} --auth-type AWS_IAM',
        'terraform': 'resource "aws_lambda_function_url" "url" {{\n  function_name      = "{resource_id}"\n  authorization_type = "AWS_IAM"\n}}',
        'rollback': None,
        'framework_refs': ['ISO A.13.1.1', 'SOC2 CC6.1'],
    },
    'No Env Encryption': {
        'title': 'Encrypt Lambda Environment Variables with KMS',
        'impact': 'High',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Create or choose an existing KMS CMK',
            'Navigate to Lambda Console → Select function → Configuration → Environment variables',
            'Click Edit → Enable helpers for encryption in transit',
            'Select your KMS key and encrypt each variable',
        ],
        'cli': 'aws lambda update-function-configuration --function-name {resource_id} --kms-key-arn <kms-key-arn>',
        'terraform': 'resource "aws_lambda_function" "fn" {{\n  function_name = "{resource_id}"\n  kms_key_arn   = aws_kms_key.lambda.arn\n}}',
        'rollback': None,
        'framework_refs': ['ISO A.10.1.1', 'SOC2 CC6.1'],
    },
    # ── CloudTrail ──
    'No CloudTrail': {
        'title': 'Enable AWS CloudTrail',
        'impact': 'Critical',
        'effort': 'Medium',
        'auto_capable': True,
        'steps': [
            'Navigate to CloudTrail Console → Create trail',
            'Enable multi-region trail',
            'Enable log file validation',
            'Configure S3 bucket for log storage (with encryption)',
            'Optionally send to CloudWatch Logs for real-time alerts',
        ],
        'cli': 'aws cloudtrail create-trail --name cloudguard-trail --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name cloudguard-trail',
        'terraform': 'resource "aws_cloudtrail" "main" {{\n  name                          = "cloudguard-trail"\n  s3_bucket_name                = aws_s3_bucket.trail.id\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n  include_global_service_events = true\n}}',
        'rollback': None,
        'framework_refs': ['CIS 3.1', 'ISO A.12.4.1', 'SOC2 CC7.2'],
    },
    # ── GuardDuty ──
    'No GuardDuty': {
        'title': 'Enable Amazon GuardDuty',
        'impact': 'High',
        'effort': 'Low',
        'auto_capable': True,
        'steps': [
            'Navigate to GuardDuty Console → Get started',
            'Click Enable GuardDuty',
            'Configure notification channel (SNS) for findings',
            'Review and tune initial findings after 24-48 hours',
        ],
        'cli': 'aws guardduty create-detector --enable',
        'terraform': 'resource "aws_guardduty_detector" "main" {{\n  enable = true\n}}',
        'rollback': 'aws guardduty delete-detector --detector-id <detector-id>',
        'framework_refs': ['CIS 3.8', 'ISO A.12.2.1', 'SOC2 CC7.1'],
    },
    # ── Config ──
    'No Config': {
        'title': 'Enable AWS Config',
        'impact': 'Medium',
        'effort': 'Medium',
        'auto_capable': True,
        'steps': [
            'Navigate to AWS Config Console → Get started',
            'Enable recording for all resource types',
            'Configure S3 bucket for delivery channel',
            'Set up Config Rules for continuous compliance evaluation',
        ],
        'cli': 'aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<role-arn>,recordingGroup={{allSupported=true}}\naws configservice start-configuration-recorder --configuration-recorder-name default',
        'terraform': 'resource "aws_config_configuration_recorder" "main" {{\n  role_arn = aws_iam_role.config.arn\n  recording_group {{\n    all_supported = true\n  }}\n}}',
        'rollback': None,
        'framework_refs': ['CIS 3.5', 'ISO A.12.4.1', 'SOC2 CC7.2'],
    },
}


class RemediationService:
    @staticmethod
    def _normalize_provider(provider):
        return (provider or '').strip().lower()

    @staticmethod
    def _framework_refs(framework, control_id):
        refs = []
        if framework and control_id:
            refs.append(f"{framework.upper()}:{control_id}")
        elif framework:
            refs.append(framework.upper())
        return refs

    @staticmethod
    def _benchmark_link(provider, framework):
        framework_key = (framework or '').replace('-', '').replace('_', '').lower()
        if framework_key in FRAMEWORK_DOCS:
            return FRAMEWORK_DOCS[framework_key]
        provider_key = RemediationService._normalize_provider(provider)
        return PROVIDER_DOCS.get(provider_key)

    @staticmethod
    def _resource_summary(resource_type):
        lowered = (resource_type or '').strip().lower()
        for token, summary in RESOURCE_GUIDES.items():
            if token in lowered:
                return summary
        return 'Review the impacted resource configuration and remove the unsafe setting identified by this check.'

    @staticmethod
    def _default_steps(title, resource_type, provider):
        provider_label = (provider or 'cloud').upper()
        return [
            f'Review the finding evidence and confirm why "{title}" was triggered.',
            f'Inspect the affected {resource_type or "resource"} in the {provider_label} console.',
            RemediationService._resource_summary(resource_type),
            'Re-run the scan to verify the control is now passing.',
        ]

    @staticmethod
    def _fallback_playbook(
        finding_title,
        resource_id=None,
        provider=None,
        control_id=None,
        resource_type=None,
        remediation_text=None,
        remediation_cli=None,
        remediation_terraform=None,
        playbook_url=None,
        framework=None,
        severity=None,
    ):
        severity_label = (severity or 'Unknown').title()
        docs_url = playbook_url or RemediationService._benchmark_link(provider, framework)
        title = f'Remediate: {finding_title or control_id or "Security Finding"}'
        steps = []
        if remediation_text:
            if isinstance(remediation_text, list):
                steps = [str(step).strip() for step in remediation_text if step]
            else:
                steps = [part.strip() for part in str(remediation_text).split('|') if part.strip() and not part.strip().startswith(('CLI:', 'Docs:', 'Solution PDF:', 'Frameworks:'))]
        if not steps:
            steps = RemediationService._default_steps(finding_title, resource_type, provider)

        return {
            'title': title,
            'impact': severity_label,
            'effort': 'Medium',
            'auto_capable': False,
            'steps': steps,
            'cli': remediation_cli or None,
            'terraform': remediation_terraform or None,
            'rollback': None,
            'framework_refs': RemediationService._framework_refs(framework, control_id),
            'docs': docs_url,
            'solution_pdf': FRAMEWORK_DOCS.get((framework or '').replace('-', '').replace('_', '').lower()),
            'summary': f'Fallback guidance generated for {resource_type or "resource"} because an exact playbook was not available.',
            'resource_id': resource_id or '<RESOURCE_ID>',
        }

    @staticmethod
    def get_playbook(
        finding_title,
        resource_id=None,
        provider=None,
        control_id=None,
        resource_type=None,
        remediation_text=None,
        remediation_cli=None,
        remediation_terraform=None,
        playbook_url=None,
        framework=None,
        severity=None,
    ):
        """Match a finding title to a remediation playbook and interpolate resource_id."""
        playbook = None
        for pattern, pb in PLAYBOOKS.items():
            if pattern in (finding_title or ''):
                playbook = dict(pb)
                break

        if not playbook:
            return RemediationService._fallback_playbook(
                finding_title,
                resource_id=resource_id,
                provider=provider,
                control_id=control_id,
                resource_type=resource_type,
                remediation_text=remediation_text,
                remediation_cli=remediation_cli,
                remediation_terraform=remediation_terraform,
                playbook_url=playbook_url,
                framework=framework,
                severity=severity,
            )

        # Interpolate resource_id into CLI/terraform templates
        rid = resource_id or '<RESOURCE_ID>'
        if playbook.get('cli'):
            playbook['cli'] = playbook['cli'].format(resource_id=rid)
        if playbook.get('terraform'):
            playbook['terraform'] = playbook['terraform'].format(resource_id=rid)
        if playbook.get('rollback'):
            playbook['rollback'] = playbook['rollback'].format(resource_id=rid)

        playbook['docs'] = playbook_url or PROVIDER_DOCS.get(RemediationService._normalize_provider(provider))
        playbook['solution_pdf'] = FRAMEWORK_DOCS.get((framework or '').replace('-', '').replace('_', '').lower())
        playbook['summary'] = f'Actionable playbook matched for {finding_title}.'
        if framework and control_id:
            refs = list(playbook.get('framework_refs') or [])
            explicit_ref = f"{framework.upper()}:{control_id}"
            if explicit_ref not in refs:
                refs.append(explicit_ref)
            playbook['framework_refs'] = refs

        return playbook

    @staticmethod
    def get_remediation_summary(scan_id):
        """
        Aggregate remediation intelligence for an entire scan:
        how many findings are auto-remediable, effort breakdown, etc.
        """
        from ..models.models import Finding
        findings = Finding.query.filter_by(scan_id=scan_id).filter(
            Finding.status.in_(['FAIL', 'NON_COMPLIANT'])
        ).all()

        auto_count = 0
        manual_count = 0
        effort_breakdown = {'Low': 0, 'Medium': 0, 'High': 0}
        impact_breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

        for f in findings:
            pb = RemediationService.get_playbook(
                f.title,
                f.resource_id,
                provider=f.cloud_provider,
                control_id=f.control_id,
                resource_type=f.resource_type,
                remediation_text=f.remediation_steps,
                remediation_cli=f.remediation_cli,
                remediation_terraform=f.remediation_terraform,
                playbook_url=f.playbook_url,
                framework=f.framework,
                severity=f.severity,
            )
            if pb['auto_capable']:
                auto_count += 1
            else:
                manual_count += 1
            effort_breakdown[pb.get('effort', 'Medium')] = effort_breakdown.get(pb.get('effort', 'Medium'), 0) + 1
            impact_breakdown[pb.get('impact', 'Medium')] = impact_breakdown.get(pb.get('impact', 'Medium'), 0) + 1

        return {
            'total_findings': len(findings),
            'auto_remediable': auto_count,
            'manual_required': manual_count,
            'effort_breakdown': effort_breakdown,
            'impact_breakdown': impact_breakdown,
        }
