# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from remediation_registry.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
REMEDIATIONS = {
  "CIS-GCP-1.4": {
    "summary": "Remove basic IAM roles (Owner, Editor, Viewer) assigned to users.",
    "steps": [
      "Identify the user with the basic role (Owner/Editor/Viewer).",
      "Assign granular, least-privilege predefined roles instead (e.g., 'roles/storage.admin' instead of 'roles/owner').",
      "Remove the basic role binding from the IAM policy."
    ],
    "documentation": [
      {
        "title": "GCP IAM Best Practices",
        "url": "https://cloud.google.com/iam/docs/using-iam-securely"
      },
      {
        "title": "CIS GCP Benchmark 1.4",
        "url": "https://www.cisecurity.org/benchmark/google_cloud_computing_platform"
      }
    ],
    "cli_example": "gcloud projects remove-iam-policy-binding PROJECT_ID --member=user:EMAIL --role=roles/owner"
  },
  "CIS-GCP-1.5": {
    "summary": "Service accounts should not be assigned basic roles (Owner, Editor, Viewer).",
    "steps": [
      "Identify the service account with the basic role.",
      "Replace the basic role with specific service-level roles required for the application.",
      "Remove the basic role binding."
    ],
    "documentation": [
      {
        "title": "Service Account Best Practices",
        "url": "https://cloud.google.com/iam/docs/best-practices-service-accounts"
      }
    ],
    "cli_example": "gcloud projects remove-iam-policy-binding PROJECT_ID --member=serviceAccount:SA_EMAIL --role=roles/editor"
  },
  "CIS-GCP-5.2": {
      "summary": "Ensure that Cloud Storage buckets have Uniform Bucket-Level Access enabled.",
      "steps": [
          "Go to the Cloud Storage browser in the Google Cloud Console.",
          "Click the name of the bucket.",
          "Select the 'Configuration' tab.",
          "Click 'Edit' under 'Access Control'.",
          "Select 'Uniform' and click 'Save'."
      ],
      "documentation": [
          {
              "title": "Use Uniform Bucket-Level Access",
              "url": "https://cloud.google.com/storage/docs/uniform-bucket-level-access"
          }
      ],
      "cli_example": "gcloud storage buckets update gs://BUCKET_NAME --uniform-bucket-level-access"
  },
  "CIS-GCP-6.2": {
      "summary": "Ensure Cloud SQL instances do not have public IP addresses (0.0.0.0/0).",
      "steps": [
          "Go to Cloud SQL in the Google Cloud Console.",
          "Select the SQL instance.",
          "Click 'Edit'.",
          "Under 'Authorized networks', remove 0.0.0.0/0 or restrict to specific IP ranges.",
          "Consider using Private IP instead of Public IP."
      ],
      "documentation": [
          {
              "title": "Cloud SQL Network Configuration",
              "url": "https://cloud.google.com/sql/docs/mysql/configure-ip"
          }
      ],
      "cli_example": "gcloud sql instances patch INSTANCE_NAME --authorized-networks=SPECIFIC_IP/32"
  },
  "CIS-GCP-6.3": {
      "summary": "Ensure Cloud SQL instances have automated backups enabled.",
      "steps": [
          "Go to Cloud SQL in the Google Cloud Console.",
          "Select the SQL instance.",
          "Click 'Edit'.",
          "Under 'Backups', enable 'Automated backups'.",
          "Set appropriate backup retention period."
      ],
      "documentation": [
          {
              "title": "Cloud SQL Backups",
              "url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups"
          }
      ],
      "cli_example": "gcloud sql instances patch INSTANCE_NAME --backup-start-time=HH:MM --enable-bin-log"
  },
  "CIS-GCP-5.3": {
      "summary": "Ensure Cloud Storage buckets have versioning enabled.",
      "steps": [
          "Go to Cloud Storage in the Google Cloud Console.",
          "Select the bucket.",
          "Click 'Edit'.",
          "Under 'Protection', enable 'Object versioning'."
      ],
      "documentation": [
          {
              "title": "Object Versioning",
              "url": "https://cloud.google.com/storage/docs/object-versioning"
          }
      ],
      "cli_example": "gsutil versioning set on gs://BUCKET_NAME"
  }
}

# Alias sub-rules to main rule
REMEDIATIONS["CIS-GCP-1.4-Users"] = REMEDIATIONS["CIS-GCP-1.4"]
REMEDIATIONS["CIS-GCP-1.4-SAs"] = REMEDIATIONS["CIS-GCP-1.5"] # Use 1.5 logic for SAs as it's about SA privs

# --- AWS REMEDIATIONS ---
REMEDIATIONS["CIS-AWS-5.2"] = {
    "summary": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22.",
    "steps": [
        "Identify the Security Group allowing 0.0.0.0/0 on port 22.",
        "Edit the inbound rules.",
        "Remove the rule allowing 0.0.0.0/0.",
        "Add specific IP ranges or other Security Groups as source."
    ],
    "documentation": [{"title": "AWS Security Group Rules", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"}],
    "cli_example": "aws ec2 revoke-security-group-ingress --group-id sg-xxxx --protocol tcp --port 22 --cidr 0.0.0.0/0"
}

REMEDIATIONS["CIS-AWS-2.1.1"] = {
    "summary": "Ensure S3 Block Public Access is enabled.",
    "steps": [
        "Go to the S3 bucket permissions.",
        "Edit 'Block public access (bucket settings)'.",
        "Check 'Block *all* public access'.",
        "Save changes."
    ],
    "documentation": [{"title": "S3 Block Public Access", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"}],
    "cli_example": "aws s3api put-public-access-block --bucket MY_BUCKET --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
}

REMEDIATIONS["CIS-AWS-1.7-IaC"] = {
   "summary": "Ensure IAM policies do not allow full '*:*' administrative privileges.",
   "steps": [
       "Identify the IAM policy with 'Effect': 'Allow', 'Action': '*', 'Resource': '*'.",
       "Refine the policy to use least-privilege actions and specific resources."
   ],
   "documentation": [{"title": "IAM Least Privilege", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"}],
   "cli_example": "aws iam create-policy-version --policy-arn ARN --policy-document file://new_policy.json --set-as-default"
}

# --- Azure REMEDIATIONS ---
REMEDIATIONS["CIS-Azure-3.1"] = {
    "summary": "Ensure that 'Secure Transfer Required' is set to 'Enabled' for Storage Accounts.",
    "steps": [
        "Go to the Storage Account configuration.",
        "Set 'Secure transfer required' to 'Enabled'."
    ],
    "documentation": [{"title": "Azure Storage Secure Transfer", "url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"}],
    "cli_example": "az storage account update --name NAME --resource-group RG --https-only true"
}

REMEDIATIONS["CIS-Azure-6.1"] = {
    "summary": "Ensure that RDP access is restricted from the internet.",
    "steps": [
        "Identify the NSG rule allowing RDP (Port 3389) from 'Any' or 'Internet'.",
        "Update the source to specific IP ranges or deny the traffic."
    ],
    "documentation": [{"title": "Azure Network Security Groups", "url": "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"}],
    "cli_example": "az network nsg rule update --resource-group RG --nsg-name NSG --name RULE --access Deny"
}

# --- Azure EXPANDED REMEDIATIONS ---
REMEDIATIONS.update({
    "CIS-Azure-3.7": {
        "summary": "Ensure default network access rule for Storage Accounts is set to Deny.",
        "steps": ["Go to Storage Account -> Networking.", "Set 'Allow access from' to 'Selected networks'.", "Ensure default action is Deny."],
        "documentation": [{"title": "Storage Network Rules", "url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"}],
        "cli_example": "az storage account update --name NAME --default-action Deny"
    },
    "CIS-Azure-8.1": {
        "summary": "Ensure that Key Vault is recoverable (Purge Protection).",
        "steps": ["Enable Purge Protection on the Key Vault."],
        "documentation": [{"title": "Key Vault Recovery", "url": "https://docs.microsoft.com/azure/key-vault/general/soft-delete-overview"}],
        "cli_example": "az keyvault update --name NAME --enable-purge-protection true"
    },
     "CIS-Azure-8.2": {
        "summary": "Ensure that Key Vault has Soft Delete enabled.",
        "steps": ["Enable Soft Delete on the Key Vault."],
        "documentation": [{"title": "Key Vault Soft Delete", "url": "https://docs.microsoft.com/azure/key-vault/general/soft-delete-overview"}],
        "cli_example": "az keyvault update --name NAME --enable-soft-delete true"
    },
    "CIS-Azure-7.1": {
        "summary": "Ensure Virtual Machines utilize Managed Disks.",
        "steps": ["Migrate VM to Managed Disks."],
        "documentation": [{"title": "Migrate to Managed Disks", "url": "https://docs.microsoft.com/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks"}],
        "cli_example": "az vm convert --resource-group RG --name VM"
    },
    "CIS-Azure-7.2-Encryption": {
        "summary": "Ensure Virtual Machine disks are encrypted.",
        "steps": ["Enable Azure Disk Encryption."],
        "documentation": [{"title": "Azure Disk Encryption", "url": "https://docs.microsoft.com/azure/virtual-machines/linux/disk-encryption-overview"}],
        "cli_example": "az vm encryption enable --resource-group RG --name VM --disk-encryption-keyvault KV"
    },
    "CIS-Azure-1.2": {
        "summary": "Ensure MFA Policy exists.",
        "steps": ["Create a Conditional Access Policy requiring MFA for all users."],
        "documentation": [{"title": "Azure MFA Policy", "url": "https://docs.microsoft.com/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa"}],
        "cli_example": "N/A (Use Portal or Graph API)"
    },
    "CIS-Azure-4.4": {
        "summary": "Ensure Transparent Data Encryption is enabled (SQL).",
        "steps": ["Go to SQL Database -> Transparent Data Encryption.", "Set to On."],
        "documentation": [{"title": "Sql TDE", "url": "https://docs.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview"}],
        "cli_example": "az sql db tde set --resource-group RG --server SERVER --database DB --status Enabled"
    },
    "CIS-Azure-6.7": {
        "summary": "Ensure that Azure Firewall is deployed.",
        "steps": ["Deploy Azure Firewall to the VNet."],
        "documentation": [{"title": "Azure Firewall", "url": "https://docs.microsoft.com/azure/firewall/tutorial-firewall-deploy-portal"}],
        "cli_example": "az network firewall create --name FW --resource-group RG --location LOC"
    },
    "CIS-Azure-8.2-Logging": {
        "summary": "Ensure Key Vault has Diagnostic Logging enabled.",
        "steps": ["Go to Key Vault -> Diagnostic Settings.", "Enable logging to Storage/EventHub/LogAnalytics."],
        "documentation": [{"title": "Key Vault Logging", "url": "https://docs.microsoft.com/azure/key-vault/general/logging"}],
        "cli_example": "az monitor diagnostic-settings create --resource RESOURCE_ID --name 'LogAudit' --logs '[{\"category\": \"AuditEvent\",\"enabled\": true}]'"
    }
})

# --- AWS EXPANDED REMEDIATIONS ---
REMEDIATIONS.update({
    "CIS-AWS-1.4": {
        "summary": "Ensure access keys are rotated every 90 days or less.",
        "steps": ["Create a new access key.", "Update applications to use the new key.", "Deactivate and delete the old key."],
        "documentation": [{"title": "Rotating Access Keys", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#RotatingAccessKeys"}],
        "cli_example": "aws iam create-access-key --user-name USER"
    },
    "CIS-AWS-1.5": {
        "summary": "Ensure no root account access key exists.",
        "steps": ["Log in as root.", "Go to Security Credentials.", "Delete all root access keys."],
        "documentation": [{"title": "Locking Root User", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"}],
        "cli_example": "aws iam delete-access-key --access-key-id KEY --user-name root"
    },
    "CIS-AWS-1.6": {
        "summary": "Ensure MFA is enabled for the 'root' user account.",
        "steps": ["Log in as root.", "Go to IAM Dashboard.", "Enable MFA for root user."],
        "documentation": [{"title": "Enable Root MFA", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"}],
        "cli_example": "N/A (Console Only)"
    },
    "CIS-AWS-1.7": {
        "summary": "Ensure hardware MFA is enabled for the 'root' user account.",
        "steps": ["Purchase a hardware MFA device (YubiKey/Gemalto).", "Sync with AWS Root account."],
        "documentation": [{"title": "Hardware MFA", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html"}],
        "cli_example": "N/A (Console Only)"
    },
    "CIS-AWS-1.8": {
        "summary": "Ensure MFA is enabled for all IAM users with a console password.",
        "steps": ["Identify users with console access.", "Enforce MFA via IAM Policy or manually enable it."],
        "documentation": [{"title": "IAM User MFA", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"}],
        "cli_example": "aws iam enable-mfa-device --user-name USER --serial-number ARN --authentication-code1 CODE1 --authentication-code2 CODE2"
    },
    "CIS-AWS-2.1.2": {
        "summary": "Ensure S3 Block public access (bucket settings) 'IgnorePublicAcls' is True.",
        "steps": ["Go to S3 Bucket Permissions.", "Edit Block Public Access.", "Enable 'IgnorePublicAcls'."],
        "documentation": [{"title": "S3 Block Public Access", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"}],
        "cli_example": "aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration IgnorePublicAcls=true"
    },
    "CIS-AWS-2.1.3": {
        "summary": "Ensure S3 Bucket Versioning is enabled.",
        "steps": ["Go to S3 Bucket Properties.", "Edit Bucket Versioning.", "Select 'Enable'."],
        "documentation": [{"title": "S3 Versioning", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"}],
        "cli_example": "aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled"
    },
    "CIS-AWS-2.2.1": {
        "summary": "Ensure all S3 buckets employ encryption-at-rest.",
        "steps": ["Go to S3 Bucket Properties.", "Edit Default Encryption.", "Enable Server-side encryption (SSE-S3 or KMS)."],
        "documentation": [{"title": "S3 Encryption", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"}],
        "cli_example": "aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
    },
    "CIS-AWS-2.2.2": {
        "summary": "Ensure S3 buckets enforce SSL.",
        "steps": ["Add a Bucket Policy denying access if 'aws:SecureTransport' is false."],
        "documentation": [{"title": "Enforce SSL S3", "url": "https://repost.aws/knowledge-center/s3-bucket-policy-for-config-rule"}],
        "cli_example": "aws s3api put-bucket-policy --bucket BUCKET --policy file://policy.json"
    },
    "CIS-AWS-3.1": {
        "summary": "Ensure CloudTrail is enabled in all regions.",
        "steps": ["Turn on CloudTrail.", "Select 'Apply to all regions' or 'Multi-region trail'."],
        "documentation": [{"title": "Creating a Trail", "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"}],
        "cli_example": "aws cloudtrail update-trail --name TRAIL --is-multi-region-trail"
    },
    "CIS-AWS-3.5": {
        "summary": "Ensure AWS Config is enabled.",
        "steps": ["Go to AWS Config.", "Turn on recording using 'Get Started'." ],
        "documentation": [{"title": "Setting Up AWS Config", "url": "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"}],
        "cli_example": "aws configservice start-configuration-recorder --configuration-recorder-name RECORDER"
    },
    "CIS-AWS-3.5-Config": {
        "summary": "Ensure AWS Config is enabled.",
        "steps": ["Go to AWS Config.", "Turn on recording using 'Get Started'." ],
        "documentation": [{"title": "Setting Up AWS Config", "url": "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"}],
        "cli_example": "aws configservice start-configuration-recorder --configuration-recorder-name RECORDER"
    },
    "CIS-AWS-LAMBDA-1": {
        "summary": "Ensure Lambda functions do not have public URLs.",
        "steps": ["Go to Lambda Configuration -> Function URL.", "Change AuthType from NONE to AWS_IAM."],
        "documentation": [{"title": "Lambda Function URLs", "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html"}],
        "cli_example": "aws lambda update-function-url-config --function-name FUNC --auth-type AWS_IAM"
    },
    "CIS-AWS-LAMBDA-2": {
        "summary": "Ensure Lambda functions use supported runtimes.",
        "steps": ["Update the function code to run on a supported runtime (e.g., python3.11, nodejs18.x)."],
        "documentation": [{"title": "Lambda Runtimes", "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"}],
        "cli_example": "aws lambda update-function-configuration --function-name FUNC --runtime python3.11"
    },
    "CIS-AWS-LAMBDA-3": {
        "summary": "Ensure Lambda environment variables are encrypted.",
        "steps": ["Enable 'Helpers for encryption in transit' or use a Customer Managed KMS key."],
        "documentation": [{"title": "Securing Env Vars", "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption"}],
        "cli_example": "aws lambda update-function-configuration --function-name FUNC --kms-key-arn ARN"
    },
    "CIS-AWS-LAMBDA-DLQ": {
        "summary": "Ensure Lambda functions have a Dead Letter Queue configured.",
        "steps": ["Configure a SQS queue or SNS topic as the DLQ for the function."],
        "documentation": [{"title": "Lambda DLQ", "url": "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#dlq"}],
        "cli_example": "aws lambda update-function-configuration --function-name FUNC --dead-letter-config TargetArn=ARN"
    },
    "CIS-AWS-GUARDDUTY-1": {
        "summary": "Ensure GuardDuty is enabled.",
        "steps": ["Go to GuardDuty console.", "Click 'Enable GuardDuty'."],
        "documentation": [{"title": "Enable GuardDuty", "url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html"}],
        "cli_example": "aws guardduty create-detector --enable"
    },
    # --- AWS RDS ---
    "CIS-AWS-RDS-1": {
        "summary": "Ensure RDS instances have encryption at rest enabled.",
        "steps": ["Create an encrypted snapshot of the unencrypted DB.", "Restore from the encrypted snapshot.", "Delete the old unencrypted instance."],
        "documentation": [{"title": "RDS Encryption", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"}],
        "cli_example": "aws rds create-db-snapshot --db-instance-identifier DB --db-snapshot-identifier SNAP && aws rds copy-db-snapshot --source-db-snapshot-identifier SNAP --target-db-snapshot-identifier SNAP-ENC --kms-key-id KEY"
    },
    "CIS-AWS-RDS-2": {
        "summary": "Ensure RDS instances are not publicly accessible.",
        "steps": ["Go to RDS Console.", "Select instance -> Modify.", "Set 'Publicly Accessible' to No."],
        "documentation": [{"title": "RDS Public Access", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"}],
        "cli_example": "aws rds modify-db-instance --db-instance-identifier DB --no-publicly-accessible --apply-immediately"
    },
    "CIS-AWS-RDS-3": {
        "summary": "Ensure RDS instances have Multi-AZ enabled for high availability.",
        "steps": ["Select instance -> Modify.", "Enable Multi-AZ deployment."],
        "documentation": [{"title": "RDS Multi-AZ", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"}],
        "cli_example": "aws rds modify-db-instance --db-instance-identifier DB --multi-az --apply-immediately"
    },
    "CIS-AWS-RDS-4": {
        "summary": "Ensure RDS instances have automated backups with adequate retention.",
        "steps": ["Select instance -> Modify.", "Set backup retention period to at least 7 days."],
        "documentation": [{"title": "RDS Backups", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"}],
        "cli_example": "aws rds modify-db-instance --db-instance-identifier DB --backup-retention-period 7 --apply-immediately"
    },
    "CIS-AWS-RDS-5": {
        "summary": "Ensure RDS instances have deletion protection enabled.",
        "steps": ["Select instance -> Modify.", "Enable Deletion Protection."],
        "documentation": [{"title": "RDS Deletion Protection", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"}],
        "cli_example": "aws rds modify-db-instance --db-instance-identifier DB --deletion-protection --apply-immediately"
    },
    "CIS-AWS-RDS-6": {
        "summary": "Ensure RDS instances have IAM Database Authentication enabled.",
        "steps": ["Select instance -> Modify.", "Enable IAM DB Authentication."],
        "documentation": [{"title": "IAM DB Auth", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html"}],
        "cli_example": "aws rds modify-db-instance --db-instance-identifier DB --enable-iam-database-authentication --apply-immediately"
    },
    "CIS-AWS-RDS-7": {
        "summary": "Ensure RDS instances have auto minor version upgrade enabled.",
        "steps": ["Select instance -> Modify.", "Enable Auto Minor Version Upgrade."],
        "documentation": [{"title": "RDS Version Upgrade", "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html"}],
        "cli_example": "aws rds modify-db-instance --db-instance-identifier DB --auto-minor-version-upgrade --apply-immediately"
    },
    # --- AWS EKS ---
    "CIS-AWS-EKS-1": {
        "summary": "Ensure EKS cluster control plane logging is enabled.",
        "steps": ["Go to EKS Console -> Cluster -> Logging.", "Enable all log types (api, audit, authenticator, controllerManager, scheduler)."],
        "documentation": [{"title": "EKS Logging", "url": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html"}],
        "cli_example": "aws eks update-cluster-config --name CLUSTER --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'"
    },
    "CIS-AWS-EKS-2": {
        "summary": "Ensure EKS cluster endpoint is not publicly accessible.",
        "steps": ["Go to EKS Console -> Cluster -> Networking.", "Disable public access or restrict to specific CIDRs."],
        "documentation": [{"title": "EKS Endpoint Access", "url": "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"}],
        "cli_example": "aws eks update-cluster-config --name CLUSTER --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true"
    },
    "CIS-AWS-EKS-3": {
        "summary": "Ensure EKS secrets are encrypted with a KMS CMK.",
        "steps": ["Create a KMS key for EKS secrets.", "Associate with cluster encryption config."],
        "documentation": [{"title": "EKS Secrets Encryption", "url": "https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html"}],
        "cli_example": "aws eks associate-encryption-config --cluster-name CLUSTER --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"arn:aws:kms:REGION:ACCOUNT:key/KEY_ID\"}}]'"
    },
    # --- AWS CloudWatch / Secrets Manager / SNS / SQS ---
    "CIS-AWS-CWL-1": {
        "summary": "Ensure CloudWatch Log Groups have a retention period set.",
        "steps": ["Go to CloudWatch -> Log Groups.", "Select group -> Edit retention -> Set to 90+ days."],
        "documentation": [{"title": "CW Log Retention", "url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html"}],
        "cli_example": "aws logs put-retention-policy --log-group-name GROUP --retention-in-days 90"
    },
    "CIS-AWS-CWL-2": {
        "summary": "Ensure CloudWatch Log Groups are encrypted with a KMS CMK.",
        "steps": ["Create a KMS key with cloudwatch logs permissions.", "Associate key with log group."],
        "documentation": [{"title": "CW Log Encryption", "url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html"}],
        "cli_example": "aws logs associate-kms-key --log-group-name GROUP --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY"
    },
    "CIS-AWS-SM-1": {
        "summary": "Ensure Secrets Manager secrets have automatic rotation enabled.",
        "steps": ["Go to Secrets Manager -> Secret.", "Enable automatic rotation with a Lambda function."],
        "documentation": [{"title": "Secrets Rotation", "url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html"}],
        "cli_example": "aws secretsmanager rotate-secret --secret-id SECRET --rotation-lambda-arn LAMBDA_ARN --rotation-rules AutomaticallyAfterDays=30"
    },
    "CIS-AWS-SM-2": {
        "summary": "Ensure Secrets Manager secrets are encrypted with a CMK.",
        "steps": ["Create a KMS CMK.", "Update the secret to use the CMK."],
        "documentation": [{"title": "Secrets Encryption", "url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html"}],
        "cli_example": "aws secretsmanager update-secret --secret-id SECRET --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY"
    },
    "CIS-AWS-SNS-1": {
        "summary": "Ensure SNS topics are encrypted with a KMS CMK.",
        "steps": ["Go to SNS Console -> Topic.", "Edit -> Enable encryption with a CMK."],
        "documentation": [{"title": "SNS Encryption", "url": "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html"}],
        "cli_example": "aws sns set-topic-attributes --topic-arn ARN --attribute-name KmsMasterKeyId --attribute-value KEY_ID"
    },
    "CIS-AWS-SQS-1": {
        "summary": "Ensure SQS queues are encrypted with a KMS CMK.",
        "steps": ["Go to SQS Console -> Queue.", "Edit -> Enable server-side encryption with a CMK."],
        "documentation": [{"title": "SQS Encryption", "url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html"}],
        "cli_example": "aws sqs set-queue-attributes --queue-url URL --attributes KmsMasterKeyId=KEY_ID"
    },
    # --- Additional missing AWS ---
    "CIS-AWS-1.1": {
        "summary": "Ensure IAM root user has no access keys.",
        "steps": ["Log in as root.", "Go to Security Credentials.", "Delete all root access keys."],
        "documentation": [{"title": "Root Access Keys", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"}],
        "cli_example": "aws iam delete-access-key --access-key-id KEY_ID --user-name root"
    },
    "CIS-AWS-1.2": {
        "summary": "Ensure MFA is enabled for all IAM users with console password.",
        "steps": ["Identify users without MFA.", "Enable MFA for each user."],
        "documentation": [{"title": "IAM MFA", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"}],
        "cli_example": "aws iam enable-mfa-device --user-name USER --serial-number ARN --authentication-code1 C1 --authentication-code2 C2"
    },
    "CIS-AWS-1.9": {
        "summary": "Ensure IAM password policy requires minimum length of 14.",
        "steps": ["Go to IAM -> Account Settings.", "Set minimum password length to 14."],
        "documentation": [{"title": "IAM Password Policy", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"}],
        "cli_example": "aws iam update-account-password-policy --minimum-password-length 14"
    },
    "CIS-AWS-1.10": {
        "summary": "Ensure IAM password policy prevents password reuse.",
        "steps": ["Go to IAM -> Account Settings.", "Set password reuse prevention to 24."],
        "documentation": [{"title": "IAM Password Policy", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"}],
        "cli_example": "aws iam update-account-password-policy --password-reuse-prevention 24"
    },
    "CIS-AWS-1.14": {
        "summary": "Ensure hardware MFA is enabled for root user.",
        "steps": ["Purchase a hardware MFA device.", "Sync with AWS root account."],
        "documentation": [{"title": "Hardware MFA", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html"}],
        "cli_example": "N/A (Console Only)"
    },
    "CIS-AWS-1.20": {
        "summary": "Ensure IAM Access Analyzer is enabled in all regions.",
        "steps": ["Go to IAM Access Analyzer.", "Create an analyzer for each active region."],
        "documentation": [{"title": "Access Analyzer", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"}],
        "cli_example": "aws accessanalyzer create-analyzer --analyzer-name my-analyzer --type ACCOUNT"
    },
    "CIS-AWS-2.8": {
        "summary": "Ensure rotation for customer-managed KMS keys is enabled.",
        "steps": ["Go to KMS Console.", "Select key -> Key Rotation -> Enable."],
        "documentation": [{"title": "KMS Key Rotation", "url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"}],
        "cli_example": "aws kms enable-key-rotation --key-id KEY_ID"
    },
    "CIS-AWS-3.2": {
        "summary": "Ensure CloudTrail log file validation is enabled.",
        "steps": ["Go to CloudTrail -> Trail.", "Enable log file validation."],
        "documentation": [{"title": "CT Log Validation", "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"}],
        "cli_example": "aws cloudtrail update-trail --name TRAIL --enable-log-file-validation"
    },
    "CIS-AWS-3.3": {
        "summary": "Ensure CloudTrail S3 bucket is not publicly accessible.",
        "steps": ["Check the S3 bucket used by CloudTrail.", "Enable Block Public Access on it."],
        "documentation": [{"title": "CT S3 Security", "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html"}],
        "cli_example": "aws s3api put-public-access-block --bucket CT-BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    },
    "CIS-AWS-3.4": {
        "summary": "Ensure CloudTrail trails are integrated with CloudWatch Logs.",
        "steps": ["Create a CloudWatch log group for CloudTrail.", "Update trail to send logs to it."],
        "documentation": [{"title": "CT CloudWatch", "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html"}],
        "cli_example": "aws cloudtrail update-trail --name TRAIL --cloud-watch-logs-log-group-arn ARN --cloud-watch-logs-role-arn ROLE_ARN"
    },
    "CIS-AWS-3.4-KMS": {
        "summary": "Ensure CloudTrail logs are encrypted at rest with KMS CMK.",
        "steps": ["Create a KMS key for CloudTrail.", "Update trail to use the key."],
        "documentation": [{"title": "CT Encryption", "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"}],
        "cli_example": "aws cloudtrail update-trail --name TRAIL --kms-key-id KEY_ARN"
    },
    "CIS-AWS-3.5-Retention": {
        "summary": "Ensure CloudWatch Log Group retention is set.",
        "steps": ["Go to CloudWatch -> Log Groups.", "Set retention to at least 90 days."],
        "documentation": [{"title": "CW Retention", "url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html"}],
        "cli_example": "aws logs put-retention-policy --log-group-name GROUP --retention-in-days 90"
    },
    "CIS-AWS-4.6": {
        "summary": "Ensure VPC flow logging is enabled in all VPCs.",
        "steps": ["Go to VPC Console -> Select VPC.", "Create flow log to CloudWatch or S3."],
        "documentation": [{"title": "VPC Flow Logs", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"}],
        "cli_example": "aws ec2 create-flow-logs --resource-type VPC --resource-ids VPC_ID --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name VPC-LOGS"
    },
    "CIS-AWS-5.1": {
        "summary": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to admin ports.",
        "steps": ["Review NACL inbound rules.", "Remove or restrict rules allowing 0.0.0.0/0."],
        "documentation": [{"title": "Network ACLs", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"}],
        "cli_example": "aws ec2 replace-network-acl-entry --network-acl-id ACL --rule-number NUM --protocol tcp --port-range From=22,To=22 --cidr-block SPECIFIC_CIDR --rule-action allow --ingress"
    },
    "CIS-AWS-5.3": {
        "summary": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (RDP).",
        "steps": ["Identify SG allowing 0.0.0.0/0 on port 3389.", "Remove the rule.", "Add specific IP ranges."],
        "documentation": [{"title": "SG Rules", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"}],
        "cli_example": "aws ec2 revoke-security-group-ingress --group-id sg-xxxx --protocol tcp --port 3389 --cidr 0.0.0.0/0"
    },
    "CIS-AWS-5.4": {
        "summary": "Ensure the default security group restricts all traffic.",
        "steps": ["Remove all inbound/outbound rules from the default security group."],
        "documentation": [{"title": "Default SG", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup"}],
        "cli_example": "aws ec2 revoke-security-group-ingress --group-id sg-default --protocol all --port all --cidr 0.0.0.0/0"
    },
    "CIS-AWS-6.1": {
        "summary": "Ensure EBS default encryption is enabled.",
        "steps": ["Go to EC2 Console -> Settings.", "Enable EBS encryption by default."],
        "documentation": [{"title": "EBS Encryption", "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"}],
        "cli_example": "aws ec2 enable-ebs-encryption-by-default"
    },
    "CIS-AWS-CUSTOM-1": {
        "summary": "Ensure EC2 instances use IMDSv2.",
        "steps": ["Modify instance metadata options.", "Set HttpTokens to 'required'."],
        "documentation": [{"title": "IMDSv2", "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"}],
        "cli_example": "aws ec2 modify-instance-metadata-options --instance-id ID --http-tokens required"
    },
    "CIS-AWS-CUSTOM-2": {
        "summary": "Ensure EC2 instances are not publicly exposed.",
        "steps": ["Remove public IPs.", "Use NAT Gateway for outbound access."],
        "documentation": [{"title": "EC2 Public IP", "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html"}],
        "cli_example": "aws ec2 modify-instance-attribute --instance-id ID --no-source-dest-check"
    },
    "CIS-AWS-CUSTOM-3": {
        "summary": "Ensure EBS volumes are encrypted.",
        "steps": ["Create encrypted snapshot.", "Create new volume from encrypted snapshot.", "Replace old volume."],
        "documentation": [{"title": "EBS Encryption", "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"}],
        "cli_example": "aws ec2 enable-ebs-encryption-by-default"
    },
    "CIS-AWS-CUSTOM-4": {
        "summary": "Ensure load balancers have access logging enabled.",
        "steps": ["Go to EC2 -> Load Balancers.", "Edit attributes -> Enable access logs."],
        "documentation": [{"title": "ALB Access Logs", "url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"}],
        "cli_example": "aws elbv2 modify-load-balancer-attributes --load-balancer-arn ARN --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=BUCKET"
    },
    "CIS-AWS-CUSTOM-S3-ACL": {
        "summary": "Ensure S3 buckets do not have public ACLs.",
        "steps": ["Go to S3 -> Bucket -> Permissions.", "Disable public ACLs via Block Public Access."],
        "documentation": [{"title": "S3 ACLs", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"}],
        "cli_example": "aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true"
    },
    "CIS-AWS-LAMBDA-4": {
        "summary": "Ensure Lambda functions are in a VPC.",
        "steps": ["Go to Lambda -> Function -> Configuration -> VPC.", "Assign VPC, subnets, and security groups."],
        "documentation": [{"title": "Lambda VPC", "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"}],
        "cli_example": "aws lambda update-function-configuration --function-name FUNC --vpc-config SubnetIds=subnet-xxx,SecurityGroupIds=sg-xxx"
    },
    # --- Azure Remediations ---
    "CIS-Azure-3.1": {
        "summary": "Ensure storage accounts require secure transfer (HTTPS).",
        "steps": ["Go to Storage Account -> Configuration.", "Set 'Secure transfer required' to Enabled."],
        "documentation": [{"title": "Azure Secure Transfer", "url": "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"}],
        "cli_example": "az storage account update --name ACCOUNT --resource-group RG --https-only true"
    },
    "CIS-Azure-3.7": {
        "summary": "Ensure default network access rule for storage accounts is deny.",
        "steps": ["Go to Storage Account -> Networking.", "Set 'Default action' to Deny."],
        "documentation": [{"title": "Storage Firewalls", "url": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security"}],
        "cli_example": "az storage account update --name ACCOUNT --resource-group RG --default-action Deny"
    },
    "CIS-Azure-4.1": {
        "summary": "Ensure SQL Server auditing is enabled.",
        "steps": ["Go to SQL Server -> Auditing.", "Enable auditing to a storage account or Log Analytics."],
        "documentation": [{"title": "SQL Auditing", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview"}],
        "cli_example": "az sql server audit-policy update --resource-group RG --server SRV --state Enabled --storage-account STORAGE"
    },
    "CIS-Azure-4.2": {
        "summary": "Ensure SQL Server threat detection is enabled.",
        "steps": ["Go to SQL Server -> Microsoft Defender for SQL.", "Enable threat detection."],
        "documentation": [{"title": "SQL Threat Detection", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-configure"}],
        "cli_example": "az sql server threat-policy update --resource-group RG --server SRV --state Enabled"
    },
    "CIS-Azure-4.4": {
        "summary": "Ensure SQL databases have TDE enabled.",
        "steps": ["Go to SQL Database -> Transparent Data Encryption.", "Enable TDE."],
        "documentation": [{"title": "TDE", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview"}],
        "cli_example": "az sql db tde set --resource-group RG --server SRV --database DB --status Enabled"
    },
    "CIS-Azure-4.6": {
        "summary": "Ensure SQL server firewall does not allow 0.0.0.0 rule.",
        "steps": ["Go to SQL Server -> Networking.", "Remove the 'Allow Azure services' rule."],
        "documentation": [{"title": "SQL Firewall", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"}],
        "cli_example": "az sql server firewall-rule delete --resource-group RG --server SRV --name AllowAllWindowsAzureIps"
    },
    "CIS-Azure-4.8": {
        "summary": "Ensure SQL Server connection policy is set to redirect.",
        "steps": ["Go to SQL Server -> Networking.", "Set connection policy to 'Redirect'."],
        "documentation": [{"title": "Connection Policy", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture"}],
        "cli_example": "az sql server conn-policy update --resource-group RG --server SRV --connection-type Redirect"
    },
    "CIS-Azure-5.2": {
        "summary": "Ensure activity logs are retained for at least 365 days.",
        "steps": ["Go to Monitor -> Activity Log -> Diagnostic Settings.", "Set retention to 365 days."],
        "documentation": [{"title": "Activity Log Retention", "url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"}],
        "cli_example": "az monitor diagnostic-settings create --resource /subscriptions/SUB --name diag --logs '[{\"category\":\"Administrative\",\"enabled\":true,\"retentionPolicy\":{\"days\":365,\"enabled\":true}}]' --storage-account STORAGE"
    },
    "CIS-Azure-6.1": {
        "summary": "Ensure RDP access is restricted from the internet.",
        "steps": ["Go to NSG -> Inbound rules.", "Remove or restrict rules allowing 0.0.0.0/0 on port 3389."],
        "documentation": [{"title": "NSG Rules", "url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"}],
        "cli_example": "az network nsg rule delete --resource-group RG --nsg-name NSG --name RULE"
    },
    "CIS-Azure-6.2": {
        "summary": "Ensure SSH access is restricted from the internet.",
        "steps": ["Go to NSG -> Inbound rules.", "Remove or restrict rules allowing 0.0.0.0/0 on port 22."],
        "documentation": [{"title": "NSG Rules", "url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"}],
        "cli_example": "az network nsg rule delete --resource-group RG --nsg-name NSG --name RULE"
    },
    "CIS-Azure-6.3": {
        "summary": "Ensure no SQL Databases allow ingress from 0.0.0.0/0.",
        "steps": ["Review SQL Server firewall rules.", "Remove any rule with 0.0.0.0 start/end IP."],
        "documentation": [{"title": "SQL Firewall", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"}],
        "cli_example": "az sql server firewall-rule delete --resource-group RG --server SRV --name AllowAll"
    },
    "CIS-Azure-6.5": {
        "summary": "Ensure Network Watcher is enabled.",
        "steps": ["Go to Network Watcher.", "Enable for each active region."],
        "documentation": [{"title": "Network Watcher", "url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview"}],
        "cli_example": "az network watcher configure --resource-group RG --locations REGION --enabled true"
    },
    "CIS-Azure-6.7": {
        "summary": "Ensure Network Watcher NSG flow logs have retention > 90 days.",
        "steps": ["Go to Network Watcher -> NSG Flow Logs.", "Set retention to at least 90 days."],
        "documentation": [{"title": "NSG Flow Logs", "url": "https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview"}],
        "cli_example": "az network watcher flow-log update --location REGION --name FLOW --nsg NSG --retention 90 --enabled true"
    },
    "CIS-Azure-7.1": {
        "summary": "Ensure Key Vault has purge protection enabled.",
        "steps": ["Go to Key Vault -> Properties.", "Enable Purge Protection (irreversible)."],
        "documentation": [{"title": "KV Purge Protection", "url": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"}],
        "cli_example": "az keyvault update --name VAULT --resource-group RG --enable-purge-protection true"
    },
    "CIS-Azure-8.1": {
        "summary": "Ensure Key Vault is recoverable (soft-delete enabled).",
        "steps": ["Key Vault soft-delete is now enabled by default and cannot be disabled."],
        "documentation": [{"title": "KV Soft-Delete", "url": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"}],
        "cli_example": "az keyvault update --name VAULT --resource-group RG --enable-soft-delete true"
    },
    "CIS-Azure-8.2": {
        "summary": "Ensure Key Vault secrets have an expiration date.",
        "steps": ["Go to Key Vault -> Secrets.", "Set expiration date on each secret."],
        "documentation": [{"title": "KV Secrets", "url": "https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets"}],
        "cli_example": "az keyvault secret set-attributes --vault-name VAULT --name SECRET --expires 2025-12-31"
    },
    "CIS-Azure-9.1": {
        "summary": "Ensure App Service uses HTTPS only.",
        "steps": ["Go to App Service -> Configuration -> General Settings.", "Set HTTPS Only to On."],
        "documentation": [{"title": "App Service HTTPS", "url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings"}],
        "cli_example": "az webapp update --resource-group RG --name APP --set httpsOnly=true"
    },
    "CIS-Azure-9.2": {
        "summary": "Ensure App Service minimum TLS version is 1.2.",
        "steps": ["Go to App Service -> TLS/SSL Settings.", "Set Minimum TLS Version to 1.2."],
        "documentation": [{"title": "App Service TLS", "url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings"}],
        "cli_example": "az webapp config set --resource-group RG --name APP --min-tls-version 1.2"
    },
    "CIS-Azure-9.3": {
        "summary": "Ensure App Service has client certificates enabled.",
        "steps": ["Go to App Service -> Configuration.", "Enable Client Certificate Mode."],
        "documentation": [{"title": "Client Certs", "url": "https://learn.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth"}],
        "cli_example": "az webapp update --resource-group RG --name APP --set clientCertEnabled=true"
    },
    "CIS-Azure-2.1": {
        "summary": "Ensure Microsoft Defender for Cloud is set to Standard tier.",
        "steps": ["Go to Microsoft Defender for Cloud -> Environment Settings.", "Set pricing tier to Standard."],
        "documentation": [{"title": "Defender Pricing", "url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview"}],
        "cli_example": "az security pricing create --name VirtualMachines --tier Standard"
    },
    "CIS-Azure-1.2": {
        "summary": "Ensure MFA is enabled for all privileged users.",
        "steps": ["Go to Azure AD -> Security -> MFA.", "Enable MFA for all admin accounts."],
        "documentation": [{"title": "Azure MFA", "url": "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted"}],
        "cli_example": "N/A (Azure AD Portal Only)"
    },
    "CIS-Azure-PG-1": {
        "summary": "Ensure PostgreSQL server has SSL enforcement enabled.",
        "steps": ["Go to PostgreSQL Server -> Connection security.", "Set SSL enforcement to Enabled."],
        "documentation": [{"title": "PG SSL", "url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-ssl-connection-security"}],
        "cli_example": "az postgres server update --resource-group RG --name SRV --ssl-enforcement Enabled"
    },
    "CIS-Azure-PG-2": {
        "summary": "Ensure PostgreSQL log checkpoints setting is enabled.",
        "steps": ["Go to PostgreSQL -> Server Parameters.", "Set log_checkpoints to ON."],
        "documentation": [{"title": "PG Logging", "url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs"}],
        "cli_example": "az postgres server configuration set --resource-group RG --server-name SRV --name log_checkpoints --value on"
    },
    "CIS-Azure-PG-3": {
        "summary": "Ensure PostgreSQL log connections setting is enabled.",
        "steps": ["Set log_connections to ON in server parameters."],
        "documentation": [{"title": "PG Logging", "url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs"}],
        "cli_example": "az postgres server configuration set --resource-group RG --server-name SRV --name log_connections --value on"
    },
    "CIS-Azure-PG-4": {
        "summary": "Ensure PostgreSQL log disconnections setting is enabled.",
        "steps": ["Set log_disconnections to ON in server parameters."],
        "documentation": [{"title": "PG Logging", "url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs"}],
        "cli_example": "az postgres server configuration set --resource-group RG --server-name SRV --name log_disconnections --value on"
    },
    "CIS-Azure-PG-5": {
        "summary": "Ensure PostgreSQL connection throttling setting is enabled.",
        "steps": ["Set connection_throttling to ON in server parameters."],
        "documentation": [{"title": "PG Throttling", "url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs"}],
        "cli_example": "az postgres server configuration set --resource-group RG --server-name SRV --name connection_throttling --value on"
    },
    "CIS-Azure-PG-6": {
        "summary": "Ensure PostgreSQL log retention days is set to > 3.",
        "steps": ["Set log_retention_days to at least 4 in server parameters."],
        "documentation": [{"title": "PG Retention", "url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs"}],
        "cli_example": "az postgres server configuration set --resource-group RG --server-name SRV --name log_retention_days --value 7"
    },
    "CIS-Azure-MySQL-1": {
        "summary": "Ensure MySQL server has SSL enforcement enabled.",
        "steps": ["Go to MySQL Server -> Connection security.", "Set SSL enforcement to Enabled."],
        "documentation": [{"title": "MySQL SSL", "url": "https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-ssl-connection-security"}],
        "cli_example": "az mysql server update --resource-group RG --name SRV --ssl-enforcement Enabled"
    },
    "CIS-Azure-ACR-1": {
        "summary": "Ensure Azure Container Registry has admin user disabled.",
        "steps": ["Go to ACR -> Access Keys.", "Disable Admin user."],
        "documentation": [{"title": "ACR Admin", "url": "https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication"}],
        "cli_example": "az acr update --name ACR --admin-enabled false"
    },
    "CIS-Azure-ACR-2": {
        "summary": "Ensure Azure Container Registry uses a Private Endpoint.",
        "steps": ["Go to ACR -> Networking.", "Add a private endpoint connection."],
        "documentation": [{"title": "ACR Private Link", "url": "https://learn.microsoft.com/en-us/azure/container-registry/container-registry-private-link"}],
        "cli_example": "az network private-endpoint create --name PE --resource-group RG --vnet-name VNET --subnet SUBNET --private-connection-resource-id ACR_ID --group-id registry --connection-name conn"
    },
    "CIS-Azure-LA-1": {
        "summary": "Ensure Log Analytics workspace retention is at least 365 days.",
        "steps": ["Go to Log Analytics Workspace -> Usage and Costs.", "Set retention to 365 days."],
        "documentation": [{"title": "LA Retention", "url": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-archive"}],
        "cli_example": "az monitor log-analytics workspace update --resource-group RG --workspace-name WS --retention-time 365"
    },
    "CIS-Azure-DISK-1": {
        "summary": "Ensure managed disks use encryption with CMK.",
        "steps": ["Create a Disk Encryption Set with a CMK.", "Associate disks with the encryption set."],
        "documentation": [{"title": "Disk CMK", "url": "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption"}],
        "cli_example": "az disk update --resource-group RG --name DISK --encryption-type EncryptionAtRestWithCustomerKey --disk-encryption-set DES_ID"
    },
    "CIS-Azure-NW-1": {
        "summary": "Ensure Network Watcher is provisioned in all regions.",
        "steps": ["Go to Network Watcher.", "Verify it is enabled for every region with resources."],
        "documentation": [{"title": "Network Watcher", "url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview"}],
        "cli_example": "az network watcher configure --resource-group NetworkWatcherRG --locations REGION --enabled true"
    },
    "CIS-Azure-8.2-Logging": {
        "summary": "Ensure diagnostic logging is enabled for Key Vault.",
        "steps": ["Go to Key Vault -> Monitoring -> Diagnostic Settings.", "Enable audit and event logging."],
        "documentation": [{"title": "KV Logging", "url": "https://learn.microsoft.com/en-us/azure/key-vault/general/logging"}],
        "cli_example": "az monitor diagnostic-settings create --resource VAULT_ID --name kv-logs --logs '[{\"category\":\"AuditEvent\",\"enabled\":true}]' --workspace WS_ID"
    },
    "CIS-Azure-CUSTOM-Admins": {
        "summary": "Ensure no more than 5 subscription owners.",
        "steps": ["Go to Subscriptions -> IAM.", "Review and reduce Owner role assignments."],
        "documentation": [{"title": "Azure RBAC", "url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/overview"}],
        "cli_example": "az role assignment list --role Owner --scope /subscriptions/SUB"
    },
    "CIS-Azure-Functions-1": {
        "summary": "Ensure Azure Functions use HTTPS only.",
        "steps": ["Go to Function App -> Configuration.", "Set HTTPS Only to On."],
        "documentation": [{"title": "Functions HTTPS", "url": "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts"}],
        "cli_example": "az functionapp update --resource-group RG --name FUNC --set httpsOnly=true"
    },
    "CIS-Azure-7.1-Backup": {
        "summary": "Ensure Key Vault keys have a backup.",
        "steps": ["Go to Key Vault -> Keys.", "Create a backup of each key."],
        "documentation": [{"title": "KV Key Backup", "url": "https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys"}],
        "cli_example": "az keyvault key backup --vault-name VAULT --name KEY --file key-backup.blob"
    },
    "CIS-Azure-7.2-Encryption": {
        "summary": "Ensure Key Vault keys use RSA 2048+ or EC P-256+.",
        "steps": ["Go to Key Vault -> Keys.", "Ensure key size is at least RSA 2048 or EC P-256."],
        "documentation": [{"title": "KV Key Types", "url": "https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys"}],
        "cli_example": "az keyvault key create --vault-name VAULT --name KEY --kty RSA --size 2048"
    },
    # --- GCP Remediations ---
    "CIS-GCP-1.1": {
        "summary": "Ensure corporate login credentials are used instead of Gmail accounts.",
        "steps": ["Use Cloud Identity or Google Workspace.", "Remove personal Gmail accounts from IAM."],
        "documentation": [{"title": "GCP Cloud Identity", "url": "https://cloud.google.com/identity/docs/overview"}],
        "cli_example": "gcloud projects get-iam-policy PROJECT --format=json"
    },
    "CIS-GCP-1.2": {
        "summary": "Ensure MFA is enabled for all users.",
        "steps": ["Go to Google Admin Console -> Security.", "Enable 2-Step Verification for the organization."],
        "documentation": [{"title": "GCP MFA", "url": "https://support.google.com/a/answer/175197"}],
        "cli_example": "N/A (Admin Console Only)"
    },
    "CIS-GCP-1.3": {
        "summary": "Ensure Security Key enforcement is used for admin accounts.",
        "steps": ["Go to Admin Console -> Security -> 2-Step Verification.", "Require security keys for admin accounts."],
        "documentation": [{"title": "Security Keys", "url": "https://support.google.com/a/answer/9176657"}],
        "cli_example": "N/A (Admin Console Only)"
    },
    "CIS-GCP-1.4-Users": {
        "summary": "Ensure no overly privileged user IAM roles (Owner/Editor to users).",
        "steps": ["Go to IAM -> Review bindings.", "Replace Owner/Editor with least-privilege roles."],
        "documentation": [{"title": "IAM Roles", "url": "https://cloud.google.com/iam/docs/understanding-roles"}],
        "cli_example": "gcloud projects remove-iam-policy-binding PROJECT --member=user:EMAIL --role=roles/owner"
    },
    "CIS-GCP-1.4-SAs": {
        "summary": "Ensure service accounts do not have admin privileges.",
        "steps": ["Audit SA bindings.", "Replace broad roles with specific roles."],
        "documentation": [{"title": "SA Best Practices", "url": "https://cloud.google.com/iam/docs/best-practices-service-accounts"}],
        "cli_example": "gcloud projects remove-iam-policy-binding PROJECT --member=serviceAccount:SA_EMAIL --role=roles/editor"
    },
    "CIS-GCP-1.5": {
        "summary": "Ensure service account has no admin privileges.",
        "steps": ["Review IAM policy.", "Remove admin roles from service accounts."],
        "documentation": [{"title": "SA Roles", "url": "https://cloud.google.com/iam/docs/best-practices-service-accounts"}],
        "cli_example": "gcloud projects get-iam-policy PROJECT --flatten='bindings[].members' --filter='bindings.members:serviceAccount AND bindings.role:roles/editor'"
    },
    "CIS-GCP-1.8": {
        "summary": "Ensure no more than 3 owners per project.",
        "steps": ["Go to IAM.", "Reduce Owner assignments to 3 or fewer."],
        "documentation": [{"title": "IAM Best Practices", "url": "https://cloud.google.com/iam/docs/using-iam-securely"}],
        "cli_example": "gcloud projects get-iam-policy PROJECT --flatten='bindings[].members' --filter='bindings.role:roles/owner'"
    },
    "CIS-GCP-1.9": {
        "summary": "Ensure crypto key rotation is <= 90 days.",
        "steps": ["Go to KMS -> Key Ring -> Key.", "Set rotation period to 90 days."],
        "documentation": [{"title": "KMS Rotation", "url": "https://cloud.google.com/kms/docs/key-rotation"}],
        "cli_example": "gcloud kms keys update KEY --keyring=RING --location=LOCATION --rotation-period=7776000s --next-rotation-time=TIME"
    },
    "CIS-GCP-1.10": {
        "summary": "Ensure KMS separation of duties (no user has both admin and encrypter/decrypter roles).",
        "steps": ["Review IAM bindings.", "Ensure no user has both roles/cloudkms.admin and roles/cloudkms.cryptoKeyEncrypterDecrypter."],
        "documentation": [{"title": "KMS IAM", "url": "https://cloud.google.com/kms/docs/iam"}],
        "cli_example": "gcloud kms keys get-iam-policy KEY --keyring=RING --location=LOCATION"
    },
    "CIS-GCP-1.12": {
        "summary": "Ensure API keys are restricted to specific APIs.",
        "steps": ["Go to APIs & Services -> Credentials.", "Edit each key to restrict to specific APIs."],
        "documentation": [{"title": "API Key Restrictions", "url": "https://cloud.google.com/docs/authentication/api-keys"}],
        "cli_example": "gcloud services api-keys update KEY_ID --api-target=service=SERVICE_NAME"
    },
    "CIS-GCP-1.13": {
        "summary": "Ensure API keys are restricted by application.",
        "steps": ["Edit API key.", "Add application restrictions (IP, HTTP referrer, etc.)."],
        "documentation": [{"title": "API Key Restrictions", "url": "https://cloud.google.com/docs/authentication/api-keys"}],
        "cli_example": "gcloud services api-keys update KEY_ID --allowed-ips=IP_RANGE"
    },
    "CIS-GCP-1.14": {
        "summary": "Ensure API keys are rotated within 90 days.",
        "steps": ["Delete old API keys.", "Generate new ones and update applications."],
        "documentation": [{"title": "API Key Rotation", "url": "https://cloud.google.com/docs/authentication/api-keys"}],
        "cli_example": "gcloud services api-keys delete KEY_ID && gcloud services api-keys create --display-name=NEW_KEY"
    },
    "CIS-GCP-1.15": {
        "summary": "Ensure service account keys are managed and rotated.",
        "steps": ["Delete user-managed SA keys.", "Use workload identity or attached service accounts instead."],
        "documentation": [{"title": "SA Key Management", "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"}],
        "cli_example": "gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL"
    },
    "CIS-GCP-1.16": {
        "summary": "Ensure primitive/basic roles are not used.",
        "steps": ["Replace Owner/Editor/Viewer bindings with predefined roles."],
        "documentation": [{"title": "Predefined Roles", "url": "https://cloud.google.com/iam/docs/understanding-roles"}],
        "cli_example": "gcloud projects remove-iam-policy-binding PROJECT --member=MEMBER --role=roles/editor"
    },
    "CIS-GCP-2.1": {
        "summary": "Ensure Cloud Audit Logging is configured properly.",
        "steps": ["Go to IAM -> Audit Logs.", "Enable Data Access audit logs for all services."],
        "documentation": [{"title": "Audit Logging", "url": "https://cloud.google.com/logging/docs/audit"}],
        "cli_example": "gcloud projects get-iam-policy PROJECT --format=json"
    },
    "CIS-GCP-2.1-CMEK": {
        "summary": "Ensure log buckets are encrypted with CMEK.",
        "steps": ["Create a KMS key for logs.", "Update log bucket to use CMEK."],
        "documentation": [{"title": "Log CMEK", "url": "https://cloud.google.com/logging/docs/routing/managed-encryption"}],
        "cli_example": "gcloud logging buckets update _Default --location=global --cmek-kms-key-name=KEY_NAME"
    },
    "CIS-GCP-2.2": {
        "summary": "Ensure log sinks are configured for all log entries.",
        "steps": ["Create an aggregated sink.", "Export logs to BigQuery, Cloud Storage, or Pub/Sub."],
        "documentation": [{"title": "Log Sinks", "url": "https://cloud.google.com/logging/docs/export"}],
        "cli_example": "gcloud logging sinks create SINK_NAME DESTINATION --log-filter=''"
    },
    "CIS-GCP-2.4": {
        "summary": "Ensure log metric filter and alert exist for project ownership changes.",
        "steps": ["Create a log metric for ownership changes.", "Create an alerting policy."],
        "documentation": [{"title": "Log Metrics", "url": "https://cloud.google.com/logging/docs/logs-based-metrics"}],
        "cli_example": "gcloud logging metrics create ownership_changes --filter='(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\") AND (ProjectOwnership OR projectOwnerInvitee)'"
    },
    "CIS-GCP-2.5": {
        "summary": "Ensure log metric for audit configuration changes.",
        "steps": ["Create log metric.", "Create alerting policy."],
        "documentation": [{"title": "Log Metrics", "url": "https://cloud.google.com/logging/docs/logs-based-metrics"}],
        "cli_example": "gcloud logging metrics create audit_config_changes --filter='protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'"
    },
    "CIS-GCP-2.6": {
        "summary": "Ensure log metric for custom role changes.",
        "steps": ["Create log metric for role creation/update/deletion.", "Set up alert."],
        "documentation": [{"title": "Custom Roles", "url": "https://cloud.google.com/iam/docs/creating-custom-roles"}],
        "cli_example": "gcloud logging metrics create custom_role_changes --filter='resource.type=\"iam_role\" AND (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")'"
    },
    "CIS-GCP-2.7": {"summary": "Ensure log metric for VPC firewall rule changes.", "steps": ["Create metric filter.", "Create alert."], "documentation": [{"title": "Firewall Logging", "url": "https://cloud.google.com/vpc/docs/firewalls"}], "cli_example": "gcloud logging metrics create fw_changes --filter='resource.type=\"gce_firewall_rule\" AND (protoPayload.methodName:\"compute.firewalls.\")'"},
    "CIS-GCP-2.8": {"summary": "Ensure log metric for VPC route changes.", "steps": ["Create metric filter.", "Create alert."], "documentation": [{"title": "VPC Routes", "url": "https://cloud.google.com/vpc/docs/routes"}], "cli_example": "gcloud logging metrics create route_changes --filter='resource.type=\"gce_route\"'"},
    "CIS-GCP-2.9": {"summary": "Ensure log metric for VPC network changes.", "steps": ["Create metric filter.", "Create alert."], "documentation": [{"title": "VPC Networks", "url": "https://cloud.google.com/vpc/docs/vpc"}], "cli_example": "gcloud logging metrics create network_changes --filter='resource.type=\"gce_network\"'"},
    "CIS-GCP-2.12": {"summary": "Ensure log metric for Cloud Storage IAM changes.", "steps": ["Create metric filter.", "Create alert."], "documentation": [{"title": "GCS IAM", "url": "https://cloud.google.com/storage/docs/access-control/iam"}], "cli_example": "gcloud logging metrics create gcs_iam_changes --filter='resource.type=\"gcs_bucket\" AND protoPayload.methodName=\"storage.setIamPermissions\"'"},
    "CIS-GCP-2.13": {"summary": "Ensure log metric for SQL instance config changes.", "steps": ["Create metric filter.", "Create alert."], "documentation": [{"title": "SQL Logging", "url": "https://cloud.google.com/sql/docs/mysql/audit-logging"}], "cli_example": "gcloud logging metrics create sql_config_changes --filter='protoPayload.methodName=\"cloudsql.instances.update\"'"},
    "CIS-GCP-2.14": {"summary": "Ensure log metric for network changes.", "steps": ["Create metric and alert."], "documentation": [{"title": "Logging", "url": "https://cloud.google.com/logging/docs"}], "cli_example": "gcloud logging metrics create network_changes --filter='resource.type=\"gce_network\"'"},
    "CIS-GCP-2.15": {"summary": "Ensure log metric for subnetwork changes.", "steps": ["Create metric and alert."], "documentation": [{"title": "VPC Subnets", "url": "https://cloud.google.com/vpc/docs/subnets"}], "cli_example": "gcloud logging metrics create subnet_changes --filter='resource.type=\"gce_subnetwork\"'"},
    "CIS-GCP-2.16": {"summary": "Ensure log metric for network peering changes.", "steps": ["Create metric and alert."], "documentation": [{"title": "VPC Peering", "url": "https://cloud.google.com/vpc/docs/vpc-peering"}], "cli_example": "gcloud logging metrics create peering_changes --filter='resource.type=\"gce_network\" AND protoPayload.methodName:\"compute.networks.addPeering\"'"},
    # --- GCP Networking ---
    "CIS-GCP-3.1": {
        "summary": "Ensure default network does not exist.",
        "steps": ["Delete the default network.", "Create a custom VPC with appropriate subnets."],
        "documentation": [{"title": "VPC Networks", "url": "https://cloud.google.com/vpc/docs/vpc"}],
        "cli_example": "gcloud compute networks delete default"
    },
    "CIS-GCP-3.2": {
        "summary": "Ensure legacy networks do not exist.",
        "steps": ["Migrate resources from legacy networks to VPC networks."],
        "documentation": [{"title": "Legacy Networks", "url": "https://cloud.google.com/vpc/docs/legacy"}],
        "cli_example": "gcloud compute networks list --filter='x_gcloud_subnet_mode:LEGACY'"
    },
    "CIS-GCP-3.2-IaC": {"summary": "Ensure legacy networks are not used in IaC.", "steps": ["Use 'auto' or 'custom' mode VPC networks."], "documentation": [{"title": "VPC", "url": "https://cloud.google.com/vpc/docs/vpc"}], "cli_example": "N/A (Terraform review)"},
    "CIS-GCP-3.3": {"summary": "Ensure DNSSEC is enabled for Cloud DNS zones.", "steps": ["Go to Cloud DNS -> Zone.", "Enable DNSSEC."], "documentation": [{"title": "DNSSEC", "url": "https://cloud.google.com/dns/docs/dnssec"}], "cli_example": "gcloud dns managed-zones update ZONE --dnssec-state on"},
    "CIS-GCP-3.4": {"summary": "Ensure RSASHA1 is not used for key-signing in DNSSEC.", "steps": ["Update DNSSEC config to use stronger algorithms."], "documentation": [{"title": "DNSSEC Config", "url": "https://cloud.google.com/dns/docs/dnssec-config"}], "cli_example": "gcloud dns managed-zones update ZONE --denial-of-existence nsec3"},
    "CIS-GCP-3.5": {"summary": "Ensure RSASHA1 is not used for zone-signing in DNSSEC.", "steps": ["Same as 3.4 - update to stronger algorithms."], "documentation": [{"title": "DNSSEC", "url": "https://cloud.google.com/dns/docs/dnssec-config"}], "cli_example": "gcloud dns managed-zones update ZONE --denial-of-existence nsec3"},
    "CIS-GCP-3.6": {"summary": "Ensure SSH access is restricted from the internet.", "steps": ["Remove firewall rules allowing 0.0.0.0/0 on port 22.", "Use IAP for SSH."], "documentation": [{"title": "IAP SSH", "url": "https://cloud.google.com/iap/docs/using-tcp-forwarding"}], "cli_example": "gcloud compute firewall-rules delete RULE_NAME"},
    "CIS-GCP-3.7": {"summary": "Ensure RDP access is restricted from the internet.", "steps": ["Remove firewall rules allowing 0.0.0.0/0 on port 3389."], "documentation": [{"title": "Firewall Rules", "url": "https://cloud.google.com/vpc/docs/firewalls"}], "cli_example": "gcloud compute firewall-rules delete RULE_NAME"},
    "CIS-GCP-3.8": {"summary": "Ensure VPC Flow Logs are enabled for subnets.", "steps": ["Go to VPC -> Subnets.", "Enable Flow Logs."], "documentation": [{"title": "VPC Flow Logs", "url": "https://cloud.google.com/vpc/docs/flow-logs"}], "cli_example": "gcloud compute networks subnets update SUBNET --region=REGION --enable-flow-logs"},
    # --- GCP Compute ---
    "CIS-GCP-4.1": {"summary": "Ensure instances do not use default service account.", "steps": ["Create a custom SA.", "Assign to the instance."], "documentation": [{"title": "Custom SA", "url": "https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances"}], "cli_example": "gcloud compute instances set-service-account INST --service-account=SA_EMAIL --zone=ZONE"},
    "CIS-GCP-4.3": {"summary": "Ensure Compute instances do not have public IP addresses.", "steps": ["Remove external IPs.", "Use Cloud NAT for outbound."], "documentation": [{"title": "Cloud NAT", "url": "https://cloud.google.com/nat/docs/overview"}], "cli_example": "gcloud compute instances delete-access-config INST --zone=ZONE --access-config-name='External NAT'"},
    "CIS-GCP-4.4": {"summary": "Ensure OS Login is enabled project-wide.", "steps": ["Set enable-oslogin metadata to TRUE."], "documentation": [{"title": "OS Login", "url": "https://cloud.google.com/compute/docs/instances/managing-instance-access"}], "cli_example": "gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE"},
    "CIS-GCP-4.5": {"summary": "Ensure OS Login 2FA is enabled for the project.", "steps": ["Set enable-oslogin-2fa metadata to TRUE."], "documentation": [{"title": "OS Login 2FA", "url": "https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication"}], "cli_example": "gcloud compute project-info add-metadata --metadata enable-oslogin-2fa=TRUE"},
    "CIS-GCP-4.6": {"summary": "Ensure block project-wide SSH keys is enabled on instances.", "steps": ["Set block-project-ssh-keys to TRUE in instance metadata."], "documentation": [{"title": "SSH Keys", "url": "https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys"}], "cli_example": "gcloud compute instances add-metadata INST --metadata block-project-ssh-keys=TRUE --zone=ZONE"},
    "CIS-GCP-4.8": {"summary": "Ensure Compute instances have Shielded VM enabled.", "steps": ["Stop instance.", "Enable Secure Boot, vTPM, and integrity monitoring."], "documentation": [{"title": "Shielded VM", "url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm"}], "cli_example": "gcloud compute instances update INST --zone=ZONE --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring"},
    "CIS-GCP-4.9": {"summary": "Ensure Compute instances do not use default service account with full API scope.", "steps": ["Assign specific OAuth scopes.", "Use custom SA."], "documentation": [{"title": "SA Scopes", "url": "https://cloud.google.com/compute/docs/access/service-accounts"}], "cli_example": "gcloud compute instances set-service-account INST --service-account=SA_EMAIL --scopes=SPECIFIC_SCOPES --zone=ZONE"},
    "CIS-GCP-4.10": {"summary": "Ensure IP forwarding is not enabled on instances.", "steps": ["Disable IP forwarding on non-gateway instances."], "documentation": [{"title": "IP Forwarding", "url": "https://cloud.google.com/vpc/docs/using-routes"}], "cli_example": "gcloud compute instances describe INST --zone=ZONE --format='get(canIpForward)'"},
    "CIS-GCP-4.11": {"summary": "Ensure Compute instances are not using deprecated images.", "steps": ["Update instances to use current OS images."], "documentation": [{"title": "Images", "url": "https://cloud.google.com/compute/docs/images"}], "cli_example": "gcloud compute images list --no-standard-images --filter='deprecated.state=DEPRECATED'"},
    # --- GCP Storage/SQL/BigQuery ---
    "CIS-GCP-5.1": {"summary": "Ensure Cloud Storage buckets are not anonymously accessible.", "steps": ["Remove allUsers and allAuthenticatedUsers from bucket IAM."], "documentation": [{"title": "Bucket IAM", "url": "https://cloud.google.com/storage/docs/access-control/iam"}], "cli_example": "gcloud storage buckets remove-iam-policy-binding gs://BUCKET --member=allUsers --role=ROLE"},
    "CIS-GCP-5.2": {"summary": "Ensure Cloud Storage uses uniform bucket-level access.", "steps": ["Enable Uniform Bucket-Level Access."], "documentation": [{"title": "UBLA", "url": "https://cloud.google.com/storage/docs/uniform-bucket-level-access"}], "cli_example": "gcloud storage buckets update gs://BUCKET --uniform-bucket-level-access"},
    "CIS-GCP-6.1-SSL": {"summary": "Ensure Cloud SQL requires SSL connections.", "steps": ["Go to SQL -> Instance -> Connections.", "Require SSL."], "documentation": [{"title": "SQL SSL", "url": "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance"}], "cli_example": "gcloud sql instances patch INST --require-ssl"},
    "CIS-GCP-6.3.5": {"summary": "Ensure Cloud SQL is not publicly accessible.", "steps": ["Remove 0.0.0.0/0 from authorized networks.", "Use private IP."], "documentation": [{"title": "SQL Private IP", "url": "https://cloud.google.com/sql/docs/mysql/private-ip"}], "cli_example": "gcloud sql instances patch INST --no-assign-ip"},
    "CIS-GCP-6.6": {"summary": "Ensure Cloud SQL database instances have backups enabled.", "steps": ["Enable automated backups."], "documentation": [{"title": "SQL Backups", "url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups"}], "cli_example": "gcloud sql instances patch INST --backup-start-time=03:00"},
    "CIS-GCP-6.7": {"summary": "Ensure Cloud SQL does not use public IP.", "steps": ["Configure private IP.", "Remove public IP."], "documentation": [{"title": "SQL Private IP", "url": "https://cloud.google.com/sql/docs/mysql/private-ip"}], "cli_example": "gcloud sql instances patch INST --no-assign-ip --network=VPC_NETWORK"},
    "CIS-GCP-7.1": {"summary": "Ensure BigQuery datasets are not anonymously accessible.", "steps": ["Remove allUsers and allAuthenticatedUsers from dataset IAM."], "documentation": [{"title": "BQ IAM", "url": "https://cloud.google.com/bigquery/docs/dataset-access-controls"}], "cli_example": "bq update --default_table_expiration 0 DATASET"},
    "CIS-GCP-7.4": {"summary": "Ensure BigQuery datasets use CMEK encryption.", "steps": ["Set default encryption key on dataset."], "documentation": [{"title": "BQ CMEK", "url": "https://cloud.google.com/bigquery/docs/customer-managed-encryption"}], "cli_example": "bq update --default_kms_key=KEY_NAME DATASET"}
})

# Merge auto-generated supplementary remediations for new CIS/SOC2/ISO rules
try:
    from remediation_supplement import REMEDIATIONS_SUPPLEMENT
    REMEDIATIONS.update(REMEDIATIONS_SUPPLEMENT)
except ImportError:
    pass  # Supplement file not yet generated
