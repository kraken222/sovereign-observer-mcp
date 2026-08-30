# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/terraform_inventory.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
import json
import logging
import re

# Setup logging
logger = logging.getLogger(__name__)


def _tls_to_number(value):
    """Convert a TLS version string like 'TLSv1.2', 'Tls12', '1.2' into a float for comparison."""
    if value is None:
        return 0.0
    s = str(value).lower().replace("tls", "").replace("v", "").strip()
    # Forms: '12' -> 1.2, '1.2' -> 1.2, '1_2' -> 1.2
    if "." in s:
        try:
            return float(s)
        except Exception:
            pass
    s_digits = re.sub(r"[^0-9]", "", s)
    if len(s_digits) == 2:
        try:
            return float(f"{s_digits[0]}.{s_digits[1]}")
        except Exception:
            return 0.0
    if s_digits.isdigit():
        try:
            return float(s_digits)
        except Exception:
            return 0.0
    return 0.0


def extract_resources(module):
    """Recursively extract resources from TF plan modules in planned_values"""
    resources = module.get("resources", [])
    for child in module.get("child_modules", []):
        resources += extract_resources(child)
    return resources

def normalize_iam_members(iam_resources):
    """
    Aggregate IAM bindings and members into a synthetic policy structure.
    Returns a unified IAMPolicy object with 'bindings' list.
    Supports both GCP and AWS IAM resources.
    """
    if not iam_resources:
        return [], {}

    # Map project/account -> role -> members
    project_policies = {} 
    
    for res in iam_resources:
        values = res.get("values", {})
        r_type = res.get("type")
        
        # GCP IAM Resources
        if "project" in r_type:
            project = values.get("project", "default-project")
            role = values.get("role")
            
            if project not in project_policies:
                project_policies[project] = {}
            if role not in project_policies[project]:
                project_policies[project][role] = set()
            
            if r_type.endswith("_binding"):
                members = values.get("members", [])
                for m in members:
                    project_policies[project][role].add(m)
            elif r_type.endswith("_member"):
                member = values.get("member")
                if member:
                    project_policies[project][role].add(member)
        elif "service_account" in r_type:
            # Service account IAM members - treat as project-level for policy evaluation
            # Extract project from service_account_id if available
            sa_id = values.get("service_account_id", "")
            # Try to extract project from service account ID format: projects/PROJECT/serviceAccounts/...
            project = "default-project"
            if "/projects/" in sa_id:
                try:
                    project = sa_id.split("/projects/")[1].split("/")[0]
                except:
                    pass
            
            role = values.get("role")
            member = values.get("member")
            
            if project not in project_policies:
                project_policies[project] = {}
            if role not in project_policies[project]:
                project_policies[project][role] = set()
            
            if member:
                project_policies[project][role].add(member)
        # AWS IAM Resources - for now, we'll collect them but AWS IAM rules are typically
        # evaluated differently (policy document analysis). This structure supports
        # basic role/user mapping if needed.
        elif r_type.startswith("aws_iam_"):
            # AWS IAM resources are handled separately in inventory
            # This section is for future expansion if needed
            pass

    # Convert to PolicyEngine compatible structure
    # Target: IAMPolicy list entries
    policies = []
    member_roles = {}

    for proj, roles in project_policies.items():
        bindings = []
        all_members = set()
        for role, members in roles.items():
            bindings.append({
                "role": role,
                "members": list(members)
            })
            all_members.update(members)
            
            # Populate member_roles reverse map
            for m in members:
                if m not in member_roles:
                     member_roles[m] = set()
                member_roles[m].add(role)
        
        policies.append({
            "name": f"project-iam-{proj}",
            "project": proj,
            "bindings": bindings,
            "members": list(all_members) 
        })
        
    return policies, member_roles

def map_terraform_to_inventory(tfplan):
    """
    Normalize Terraform Plan JSON into PolicyEngine Inventory.
    Robust handling of defaults and metadata.
    """
    inventory = {
        # GCP Resources
        "storage_bucket": [],
        "compute_instance": [],
        "kms_key": [],
        "vpc_firewall": [],
        "vpc_subnet": [],
        "sql_instance": [],
        "bigquery_dataset": [],
        "gke_cluster": [],
        "iam_policy": [],
        "iam_service_account": [],
        "org_policy": [],
        "dns_policy": [],
        "backend_service": [],
        "dns_zone": [],
        "disabled_services": [],
        # AWS Resources
        "s3_bucket": [],
        "ec2_instance": [],
        "security_group": [],
        "iam_user": [],
        "iam_role": [],
        "iam_access_key": [],
        "rds_instance": [],
        "lambda_function": [],
        "ebs_volume": [],
        "cloudtrail_trail": [],
        "load_balancer": [],
        # Azure Resources
        "azure_storage_account": [],
        "azure_key_vault": [],
        "azure_virtual_machine": [],
        "azure_sql_server": [],
        "azure_sql_database": [],
        "azure_nsg": [],
        "azure_app_service": [],
        "azure_db_server": [],
        "azure_monitor_log_profile": [],
        "azure_security_center_pricing": [],
        "azure_network_watcher": [],
        "azure_network_watcher_flow_log": [],
        "azure_firewall": [],
        "iam_policies": [],
        "cloudwatch_log_group": [],
        "gcp_service_account_key": [],
        "aws_access_analyzer": [],
        # AWS Extended
        "eks_cluster": [],
        "secrets_manager_secret": [],
        "sns_topic": [],
        "sqs_queue": [],
        "guardduty_detector": [],
        "config_recorder": [],
        # Azure Extended
        "azure_postgresql_server": [],
        "azure_mysql_server": [],
        "azure_container_registry": [],
        "azure_log_analytics_workspace": [],
        "azure_managed_disk": [],
        "azure_function": [],
        "azure_active_directory": [],
        # GCP Extended
        "logging_sink": [],
        "vpc_network": [],
        "project_service": [],
        # === Critical-checks coverage extensions ===
        # AWS — APIs, edge, container infra, observability gaps
        "apigateway_rest_api": [],
        "wafv2_web_acl": [],
        "ecs_task_definition": [],
        "ecr_repository": [],
        "opensearch_domain": [],
        "cloudfront_distribution": [],
        # Azure — managed services that ship in real workloads
        "azure_kubernetes_cluster": [],
        "azure_cosmosdb_account": [],
        "azure_redis_cache": [],
        "azure_role_assignment": [],
        "azure_application_gateway": [],
        # GCP — modern serverless / secrets / GKE deeper config
        "gcp_cloud_run_service": [],
        "gcp_cloudfunctions_function": [],
        "gcp_secret_manager_secret": [],
        "gke_cluster_security": []
    }

    # Extract planned values
    root_planned = tfplan.get("planned_values", {}).get("root_module")
    if not root_planned:
        logger.error("Invalid TF Plan: Missing root_module in planned_values")
        return inventory

    resources = extract_resources(root_planned)
    
    iam_resources = []

    for res in resources:
        try:
            r_type = res.get("type")
            values = res.get("values", {})
            full_address = res.get("address")
            
            # Common Metadata
            metadata = {
                "source_file": "terraform.tf", 
                "line": 0,
                "resource_id": full_address
            }

            def _get_val(obj, key, default=None):
                """Helper to get value whether list or dict"""
                if isinstance(obj, list):
                    if len(obj) > 0:
                        return obj[0].get(key, default)
                elif isinstance(obj, dict):
                    return obj.get(key, default)
                return default

            # --- Storage ---
            if r_type == "google_storage_bucket":
                # UBLA - Check nested iam_configuration first (User Payload pattern)
                iam_config = values.get("iam_configuration", {})
                ubla_nested = iam_config.get("uniform_bucket_level_access", {})
                ubla = ubla_nested.get("enabled", False) if isinstance(ubla_nested, dict) else False

                # Fallback to standard/flat if not found nested
                if not ubla:
                     ubla = values.get("uniform_bucket_level_access", False)

                # Versioning
                vers = values.get("versioning")
                vers_enabled = _get_val(vers, "enabled", False)
                
                # Encryption
                enc = values.get("encryption")
                kms_key = _get_val(enc, "default_kms_key_name")

                inventory["storage_bucket"].append({
                    "name": full_address,
                    "iam_configuration": {
                        "uniform_bucket_level_access": {
                            "enabled": ubla
                        }
                    },
                    "versioning": {"enabled": vers_enabled},
                    "encryption": {"default_kms_key_name": kms_key},
                    "__metadata": metadata
                })

            # --- Compute Instance ---
            elif r_type == "google_compute_instance":
                shielded = values.get("shielded_instance_config") # Can be list or dict
                secure_boot = _get_val(shielded, "enable_secure_boot", False)
                
                # Public IP
                nics = values.get("network_interface", [])
                has_public_ip = False
                for nic in nics:
                    acs = nic.get("access_config", [])
                    if acs and len(acs) > 0:
                        has_public_ip = True
                        break
                
                # Service Account
                sa_list = values.get("service_account", [])
                service_accounts = sa_list if isinstance(sa_list, list) else [sa_list] if sa_list else []
                
                # Metadata (for OsLogin / Block SSH)
                meta = values.get("metadata", {})
                
                inventory["compute_instance"].append({
                    "name": full_address,
                    "shielded_instance_config": {"enable_secure_boot": secure_boot},
                    "network_interfaces": [{"access_configs": ["exists"] if has_public_ip else []}],
                    "service_accounts": service_accounts,
                    "metadata": meta,
                    "__metadata": metadata
                })

            # --- KMS Key ---
            elif r_type == "google_kms_crypto_key":
                inventory["kms_key"].append({
                    "name": full_address,
                    "rotation_period": values.get("rotation_period"),
                    "__metadata": metadata
                })

             # --- Firewall ---
            elif r_type == "google_compute_firewall":
                 inventory["vpc_firewall"].append({
                     "name": full_address,
                     "source_ranges": values.get("source_ranges", []),
                     "allow": values.get("allow", []),
                     "deny": values.get("deny", []),
                     "direction": values.get("direction", "INGRESS"), 
                     "disabled": values.get("disabled", False),
                     "__metadata": metadata
                 })

            # --- VPC Subnet (Flow Logs) ---
            elif r_type == "google_compute_subnetwork":
                log_config = values.get("log_config", [])
                flow_logs = False
                if isinstance(log_config, list) and len(log_config) > 0:
                    flow_logs = True
                elif isinstance(log_config, dict):
                    flow_logs = True
                
                inventory["vpc_subnet"].append({
                    "name": full_address,
                    "enable_flow_logs": flow_logs,
                    "__metadata": metadata
                })

            # --- Cloud SQL ---
            elif r_type == "google_sql_database_instance":
                settings = values.get("settings")
                
                backup_enabled = False
                require_ssl = False
                ipv4_enabled = True 

                authorized_networks = []
                if settings:
                    # Helper handles list/dict safety
                    bkp = _get_val(settings, "backup_configuration")
                    if bkp:
                         # Backup config itself might be list or dict
                         backup_enabled = _get_val(bkp, "enabled", False)
                         
                    ip_cfg = _get_val(settings, "ip_configuration")
                    if ip_cfg:
                        require_ssl = _get_val(ip_cfg, "require_ssl", False)
                        ipv4_enabled = _get_val(ip_cfg, "ipv4_enabled", True)
                        # Extract authorized_networks
                        auth_nets = ip_cfg.get("authorized_networks", [])
                        if isinstance(auth_nets, list):
                            authorized_networks = [net.get("value", net) if isinstance(net, dict) else str(net) for net in auth_nets]

                inventory["sql_instance"].append({
                    "name": full_address,
                    "settings": {
                        "backup_configuration": {"enabled": backup_enabled},
                        "ip_configuration": {
                            "require_ssl": require_ssl,
                            "ipv4_enabled": ipv4_enabled,
                            "authorized_networks": authorized_networks
                        },
                        "ipv4_enabled": ipv4_enabled 
                    },
                    "__metadata": metadata
                })

            # --- BigQuery Dataset ---
            elif r_type == "google_bigquery_dataset":
                access_entries = values.get("access", [])
                public_access = False
                if isinstance(access_entries, list):
                    for entry in access_entries:
                        if not isinstance(entry, dict):
                            continue
                        special_group = str(entry.get("special_group", "")).lower()
                        iam_member = str(entry.get("iam_member", "")).lower()
                        if special_group in {"allauthenticatedusers", "allusers"} or iam_member in {"allauthenticatedusers", "allusers"}:
                            public_access = True
                            break

                inventory["bigquery_dataset"].append({
                    "name": values.get("dataset_id", full_address),
                    "location": values.get("location"),
                    "default_encryption_configuration": values.get("default_encryption_configuration", {}),
                    "access": access_entries,
                    "public_access": public_access,
                    "labels": values.get("labels", {}),
                    "__metadata": metadata
                })

            # --- GKE Cluster ---
            elif r_type == "google_container_cluster":
                private_cluster_config = values.get("private_cluster_config", [])
                private_nodes = _get_val(private_cluster_config, "enable_private_nodes", False)
                master_global_access = _get_val(private_cluster_config, "master_global_access_enabled", False)
                network_policy = values.get("network_policy", [])
                shielded_nodes = values.get("enable_shielded_nodes", False)
                binary_auth = values.get("binary_authorization", [])

                inventory["gke_cluster"].append({
                    "name": values.get("name", full_address),
                    "private_cluster_config": {
                        "enable_private_nodes": private_nodes,
                        "master_global_access_enabled": master_global_access,
                    },
                    "network_policy": {
                        "enabled": _get_val(network_policy, "enabled", False),
                    },
                    "enable_shielded_nodes": shielded_nodes,
                    "binary_authorization": {
                        "evaluation_mode": _get_val(binary_auth, "evaluation_mode", "DISABLED"),
                    },
                    "__metadata": metadata
                })

            # --- Cloud DNS Managed Zone ---
            elif r_type == "google_dns_managed_zone":
                dnssec_config = values.get("dnssec_config", [])
                default_key_specs = _get_val(dnssec_config, "default_key_specs", [])
                key_signing_algorithms = []
                zone_signing_algorithms = []
                if isinstance(default_key_specs, list):
                    for spec in default_key_specs:
                        if not isinstance(spec, dict):
                            continue
                        if spec.get("key_type") == "keySigning":
                            key_signing_algorithms.append(spec.get("algorithm"))
                        if spec.get("key_type") == "zoneSigning":
                            zone_signing_algorithms.append(spec.get("algorithm"))

                inventory["dns_zone"].append({
                    "name": values.get("name", full_address),
                    "visibility": values.get("visibility", "public"),
                    "dnssec_config": {
                        "state": _get_val(dnssec_config, "state", "off"),
                        "default_key_specs": default_key_specs,
                        "key_signing_algorithms": key_signing_algorithms,
                        "zone_signing_algorithms": zone_signing_algorithms,
                    },
                    "__metadata": metadata
                })
                
            # --- AWS S3 Bucket ---
            elif r_type == "aws_s3_bucket":
                # ... existing logic ...
                public_access_block = values.get("public_access_block", [])
                # ... existing logic ...
                block_public_acls = False
                block_public_policy = False
                ignore_public_acls = False
                restrict_public_buckets = False
                
                if isinstance(public_access_block, list) and len(public_access_block) > 0:
                    pab = public_access_block[0]
                    block_public_acls = pab.get("block_public_acls", False)
                    block_public_policy = pab.get("block_public_policy", False)
                    ignore_public_acls = pab.get("ignore_public_acls", False)
                    restrict_public_buckets = pab.get("restrict_public_buckets", False)
                elif isinstance(public_access_block, dict):
                    block_public_acls = public_access_block.get("block_public_acls", False)
                    block_public_policy = public_access_block.get("block_public_policy", False)
                    ignore_public_acls = public_access_block.get("ignore_public_acls", False)
                    restrict_public_buckets = public_access_block.get("restrict_public_buckets", False)
                
                # Check ACL
                acl = values.get("acl", "private")
                has_public_acl = acl in ["public-read", "public-read-write", "authenticated-read"]
                
                # Check Policy for SSL Enforcement (aws:SecureTransport)
                policy_json = values.get("policy")
                enforces_ssl = False
                if policy_json:
                    try:
                        if isinstance(policy_json, str):
                            policy = json.loads(policy_json)
                        else:
                            policy = policy_json
                        
                        statements = policy.get("Statement", [])
                        if isinstance(statements, dict): statements = [statements]
                        
                        for stmt in statements:
                            effect = stmt.get("Effect")
                            condition = stmt.get("Condition", {})
                            # Check for Deny non-SSL OR Allow only SSL
                            # Standard pattern: Deny if aws:SecureTransport is false
                            bool_cond = condition.get("Bool", {})
                            if effect == "Deny":
                                if "aws:SecureTransport" in bool_cond:
                                    val = bool_cond["aws:SecureTransport"]
                                    if val == "false" or val == False:
                                        enforces_ssl = True
                    except:
                        pass

                # Versioning
                versioning = values.get("versioning", {})
                versioning_enabled = False
                if isinstance(versioning, list) and len(versioning) > 0:
                    versioning_enabled = versioning[0].get("enabled", False)
                elif isinstance(versioning, dict):
                    versioning_enabled = versioning.get("enabled", False)
                
                # Encryption
                server_side_encryption_configuration = values.get("server_side_encryption_configuration", [])
                encryption_enabled = False
                if isinstance(server_side_encryption_configuration, list) and len(server_side_encryption_configuration) > 0:
                    rule = server_side_encryption_configuration[0].get("rule", {})
                    if isinstance(rule, list) and len(rule) > 0:
                        encryption_enabled = rule[0].get("apply_server_side_encryption_by_default", {}) is not None
                    elif isinstance(rule, dict):
                        encryption_enabled = rule.get("apply_server_side_encryption_by_default", {}) is not None
                elif isinstance(server_side_encryption_configuration, dict):
                    rule = server_side_encryption_configuration.get("rule", {})
                    # ... 
                    encryption_enabled = True # Simplified check if dict exists

                # Composite check for "Block Public Access enabled" (CIS generic check)
                bpa_enabled = block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets
                
                inventory["s3_bucket"].append({
                    "name": values.get("bucket", full_address),
                    "acl": acl,
                    "has_public_acl": has_public_acl,
                    "public_access_block": {
                        "block_public_acls": block_public_acls,
                        "block_public_policy": block_public_policy,
                        "ignore_public_acls": ignore_public_acls,
                        "restrict_public_buckets": restrict_public_buckets,
                        "enabled": bpa_enabled  # Alias for unified CIS rule compatibility
                    },
                    "versioning": {"enabled": versioning_enabled},
                    "server_side_encryption_configuration": {"enabled": encryption_enabled},
                    "encryption": {"enabled": encryption_enabled}, # Alias for unified CIS rule compatibility
                    "enforces_ssl": enforces_ssl,
                    "__metadata": metadata
                })

            # --- AWS IAM Policy (Check for *:* and MFA) ---
            elif r_type == "aws_iam_policy":
                policy_doc = values.get("policy")
                has_star_star = False
                if policy_doc:
                    try:
                        if isinstance(policy_doc, str): doc = json.loads(policy_doc)
                        else: doc = policy_doc
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict): statements = [statements]
                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action")
                                resources = stmt.get("Resource")
                                if actions == "*" and resources == "*":
                                    has_star_star = True
                                if isinstance(actions, list) and "*" in actions and resources == "*":
                                    has_star_star = True
                    except:
                        pass
                
                inventory["iam_policies"].append({
                    "name": values.get("name", full_address),
                    "has_full_admin": has_star_star,
                    "__metadata": metadata
                })

            # --- AWS CloudTrail ---
            elif r_type == "aws_cloudtrail":
                is_multi_region = values.get("is_multi_region_trail", False)
                enable_log_file_validation = values.get("enable_log_file_validation", False)
                include_global_service_events = values.get("include_global_service_events", False)
                kms_key_id = values.get("kms_key_id")
                
                inventory["cloudtrail_trail"].append({
                    "name": values.get("name", full_address),
                    "is_multi_region_trail": is_multi_region,
                    "enable_log_file_validation": enable_log_file_validation,
                    "include_global_service_events": include_global_service_events,
                    "has_kms_key": bool(kms_key_id),
                    "__metadata": metadata
                })

            # --- AWS CloudWatch Log Group ---
            elif r_type == "aws_cloudwatch_log_group":
                retention = values.get("retention_in_days", 0)
                inventory["cloudwatch_log_group"].append({
                    "name": values.get("name", full_address),
                    "retention_in_days": retention,
                    "__metadata": metadata
                })

            # --- Azure Firewall ---
            elif r_type == "azurerm_firewall":
                inventory["azure_firewall"].append({
                    "name": values.get("name", full_address),
                    "__metadata": metadata
                })

            # --- Azure SQL Server (Threat Detection) ---
            elif r_type == "azurerm_mssql_server":
                # ... existing
                threat_policy = values.get("threat_detection_policy", [])
                threat_enabled = False
                if isinstance(threat_policy, list) and len(threat_policy) > 0:
                     threat_enabled = threat_policy[0].get("enabled", False) if isinstance(threat_policy[0], dict) else False
                elif isinstance(threat_policy, dict):
                     threat_enabled = threat_policy.get("enabled", False)

                inventory["azure_sql_server"].append({
                    "name": values.get("name", full_address),
                    "threat_detection_policy": {"enabled": threat_enabled},
                    "__metadata": metadata
                })

            # --- GCP Service Account Key ---
            elif r_type == "google_service_account_key":
                inventory["gcp_service_account_key"].append({
                    "name": full_address,
                    "service_account_id": values.get("service_account_id"),
                    "__metadata": metadata
                })

            # --- Azure Key Vault (Soft Delete) Update ---
             # Already added in previous turn logic, confirming soft_delete_retention_days extraction
             

            
            # --- AWS Load Balancer (ELB/ALB/NLB) ---
            elif r_type in ["aws_lb", "aws_elb", "aws_alb"]:
                # Access logs
                access_logs = values.get("access_logs", [])
                access_logging_enabled = False
                if isinstance(access_logs, list) and len(access_logs) > 0:
                    access_logging_enabled = access_logs[0].get("enabled", False) if isinstance(access_logs[0], dict) else bool(access_logs[0])
                elif isinstance(access_logs, dict):
                    access_logging_enabled = access_logs.get("enabled", False)
                
                inventory["load_balancer"].append({
                    "name": values.get("name", full_address),
                    "load_balancer_type": values.get("load_balancer_type", "application"),
                    "access_logs": {"enabled": access_logging_enabled},
                    "__metadata": metadata
                })
            
            # --- Collection for IAM Aggregation (GCP) ---
            elif r_type.startswith("google_project_iam") or r_type.startswith("google_storage_bucket_iam") or r_type.startswith("google_service_account_iam"):
                res["values"]["__address"] = full_address 
                iam_resources.append(res)
            
            # --- Azure Storage Account ---
            elif r_type == "azurerm_storage_account":
                enable_https = values.get("enable_https_traffic_only", True)
                network_rules = values.get("network_rules", [])
                default_action = "Allow"
                if isinstance(network_rules, list) and len(network_rules) > 0:
                    default_action = network_rules[0].get("default_action", "Allow")
                elif isinstance(network_rules, dict):
                    default_action = network_rules.get("default_action", "Allow")

                inventory["azure_storage_account"].append({
                    "name": values.get("name", full_address),
                    "enable_https_traffic_only": enable_https,
                    "network_rules": {"default_action": default_action},
                    "__metadata": metadata
                })

            # --- Azure Virtual Machine ---
            elif r_type in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"]:
                os_disk = values.get("os_disk", [])
                disk_type = "Standard_LRS" # Default assumption if missing but should be there
                if isinstance(os_disk, list) and len(os_disk) > 0:
                    disk_type = os_disk[0].get("storage_account_type", "Standard_LRS")
                elif isinstance(os_disk, dict):
                    disk_type = os_disk.get("storage_account_type", "Standard_LRS")

                inventory["azure_virtual_machine"].append({
                    "name": values.get("name", full_address),
                    "os_disk": {"managed_disk_type": disk_type},
                    "__metadata": metadata
                })

            # --- Azure SQL Server ---
            elif r_type == "azurerm_mssql_server":
                # Auditing is often a separate resource "azurerm_mssql_server_extended_auditing_policy"
                # But sometimes inline. We'll check for extended_auditing_policy block if inline
                # For this simplified scanner, we will assume if the resource exists, we check properties.
                # Realistically in Terraform, auditing is often a separate resource. 
                # We will check for inline or linked resources logic in future.
                # For now, let's look for "azurerm_mssql_server_extended_auditing_policy" separate resource
                # But here we are processing the server itself. 
                
                inventory["azure_sql_server"].append({
                    "name": values.get("name", full_address),
                    "auditing_policy": {
                        "enabled": False, # Will be updated by separate policy resource scan if we implemented that correlation
                        "audit_actions_and_groups": []
                    },
                    "__metadata": metadata
                })

            # --- Azure NSG ---
            elif r_type == "azurerm_network_security_group":
                security_rules = values.get("security_rule", [])
                
                rdp_open = []
                ssh_open = []

                for rule in security_rules:
                    access = rule.get("access")
                    # Int, string, or "*". Handle carefully.
                    dport = str(rule.get("destination_port_range")) 
                    proto = rule.get("protocol")
                    direction = rule.get("direction")
                    source = rule.get("source_address_prefix")

                    if access == "Allow" and direction == "Inbound" and source == "*":
                        if dport in ["3389", "*"] or (dport == "*" and proto in ["TCP", "*"]):
                             rdp_open.append(f"Allow-{proto}-{dport}-Internet")
                        if dport in ["22", "*"] or (dport == "*" and proto in ["TCP", "*"]):
                             ssh_open.append(f"Allow-{proto}-{dport}-Internet")

                inventory["azure_nsg"].append({
                    "name": values.get("name", full_address),
                    "security_rules": {
                        "rdp_open": rdp_open,
                        "ssh_open": ssh_open
                    },
                    "__metadata": metadata
                })

            # --- Azure Key Vault ---
            elif r_type == "azurerm_key_vault":
                purge_protection = values.get("purge_protection_enabled", False)
                soft_delete_days = values.get("soft_delete_retention_days", 90) # Default depends on provider version
                
                inventory["azure_key_vault"].append({
                    "name": values.get("name", full_address),
                    "purge_protection_enabled": purge_protection,
                    "soft_delete_retention_days": soft_delete_days,
                    "__metadata": metadata
                })

            # --- Azure App Service ---
            elif r_type in ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"]:
                site_config = values.get("site_config", [])
                https_only = values.get("https_only", False)
                client_cert_enabled = values.get("client_cert_enabled", False)
                
                # Handling site_config which is a list block
                min_tls = "1.2"
                http2 = False
                if isinstance(site_config, list) and len(site_config) > 0:
                    sc = site_config[0]
                    min_tls = sc.get("min_tls_version", "1.2")
                    http2 = sc.get("http2_enabled", False)
                elif isinstance(site_config, dict):
                    min_tls = site_config.get("min_tls_version", "1.2")
                    http2 = site_config.get("http2_enabled", False)

                inventory["azure_app_service"].append({
                    "name": values.get("name", full_address),
                    "https_only": https_only,
                    "client_cert_enabled": client_cert_enabled,
                    "site_config": {
                        "min_tls_version": min_tls,
                        "http2_enabled": http2
                    },
                    "__metadata": metadata
                })

            # --- Azure SQL Database ---
            elif r_type == "azurerm_mssql_database":
                # TDE check (transparent_data_encryption_enabled) - deprecated in 3.0 but good for some
                # tde_enabled = values.get("transparent_data_encryption_enabled", True) 
                # Actually newer resources might handle this differently, but let's capture what we can
                
                inventory["azure_sql_database"].append({
                    "name": values.get("name", full_address),
                    "server_id": values.get("server_id"),
                    "__metadata": metadata
                })

            # --- Azure Database for MySQL/PostgreSQL ---
            elif r_type in ["azurerm_mysql_server", "azurerm_postgresql_server"]:
                ssl_enforcement = values.get("ssl_enforcement_enabled", False)
                public_access = values.get("public_network_access_enabled", True)
                
                inventory["azure_db_server"].append({
                    "name": values.get("name", full_address),
                    "type": "mysql" if "mysql" in r_type else "postgresql",
                    "ssl_enforcement_enabled": ssl_enforcement,
                    "public_network_access_enabled": public_access,
                    "__metadata": metadata
                })

            # --- Azure Monitor Log Profile ---
            elif r_type == "azurerm_monitor_log_profile":
                categories = values.get("categories", [])
                locations = values.get("locations", [])
                retention = values.get("retention_policy", [])
                
                retention_enabled = False
                days = 0
                if isinstance(retention, list) and len(retention) > 0:
                    retention_enabled = retention[0].get("enabled", False)
                    days = retention[0].get("days", 0)
                elif isinstance(retention, dict):
                    retention_enabled = retention.get("enabled", False)
                    days = retention.get("days", 0)

                inventory["azure_monitor_log_profile"].append({
                    "name": values.get("name", full_address),
                    "categories": categories,
                    "locations": locations,
                    "retention_policy": {
                        "enabled": retention_enabled,
                        "days": days
                    },
                    "__metadata": metadata
                })

            # --- Azure Security Center Subscription Pricing ---
            elif r_type == "azurerm_security_center_subscription_pricing":
                tier = values.get("tier", "Free")
                inventory["azure_security_center_pricing"].append({
                    "name": full_address,
                    "tier": tier,
                    "resource_type": values.get("resource_type"),
                    "__metadata": metadata
                })
            
            # --- Azure Network Watcher ---
            elif r_type == "azurerm_network_watcher":
                inventory["azure_network_watcher"].append({
                    "name": values.get("name", full_address),
                    "location": values.get("location"),
                    "__metadata": metadata
                })

            # --- Azure Network Watcher Flow Log ---
            elif r_type == "azurerm_network_watcher_flow_log":
                retention = values.get("retention_policy", [])
                enabled = values.get("enabled", False)
                days = 0
                if isinstance(retention, list) and len(retention) > 0:
                    days = retention[0].get("days", 0)
                elif isinstance(retention, dict):
                    days = retention.get("days", 0)
                    
                inventory["azure_network_watcher_flow_log"].append({
                    "name": values.get("name", full_address),
                    "enabled": enabled,
                    "retention_policy": {"days": days},
                    "__metadata": metadata
                })

            # --- AWS IAM User ---
            elif r_type == "aws_iam_user":
                inventory["iam_user"].append({
                    "name": values.get("name", full_address),
                    "__metadata": metadata
                })

            # --- AWS IAM Access Key ---
            elif r_type == "aws_iam_access_key":
                inventory["iam_access_key"].append({
                    "name": values.get("user", "unknown"),
                    "status": values.get("status", "Active"),
                    "__metadata": metadata
                })

            # --- AWS Security Group ---
            elif r_type == "aws_security_group":
                ingress = values.get("ingress", [])
                inventory["security_group"].append({
                    "name": values.get("name", full_address),
                    "ingress": ingress,
                    "description": values.get("description", ""),
                    "__metadata": metadata
                })

            # --- AWS EC2 Instance ---
            elif r_type == "aws_instance":
                metadata_opts = values.get("metadata_options", [])
                http_tokens = "optional"
                if isinstance(metadata_opts, list) and len(metadata_opts) > 0:
                    http_tokens = metadata_opts[0].get("http_tokens", "optional")
                elif isinstance(metadata_opts, dict):
                    http_tokens = metadata_opts.get("http_tokens", "optional")

                inventory["ec2_instance"].append({
                    "name": values.get("tags", {}).get("Name", full_address),
                    "public_ip": values.get("associate_public_ip_address", False),
                    "metadata_options": {"http_tokens": http_tokens},
                    "__metadata": metadata
                })

            # --- AWS EBS Volume ---
            elif r_type == "aws_ebs_volume":
                inventory["ebs_volume"].append({
                    "name": values.get("tags", {}).get("Name", full_address),
                    "encrypted": values.get("encrypted", False),
                    "__metadata": metadata
                })

            # --- AWS RDS Instance ---
            elif r_type == "aws_db_instance":
                inventory["rds_instance"].append({
                    "name": values.get("identifier", full_address),
                    "publicly_accessible": values.get("publicly_accessible", False),
                    "storage_encrypted": values.get("storage_encrypted", False),
                    "backup_retention_period": values.get("backup_retention_period", 0),
                    "__metadata": metadata
                })

            # --- AWS KMS Key ---
            elif r_type == "aws_kms_key":
                inventory["kms_key"].append({
                    "name": values.get("description", full_address),
                    "enable_key_rotation": values.get("enable_key_rotation", False),
                    "key_usage": values.get("key_usage", "ENCRYPT_DECRYPT"),
                    "is_enabled": values.get("is_enabled", True),
                    "__metadata": metadata
                })
            
            # --- AWS Access Analyzer ---
            elif r_type == "aws_accessanalyzer_analyzer":
                inventory["aws_access_analyzer"].append({
                    "name": values.get("analyzer_name", full_address),
                    "type": values.get("type", "ACCOUNT"),
                    "__metadata": metadata
                })

            # --- AWS GuardDuty ---
            elif r_type == "aws_guardduty_detector":
                inventory["guardduty_detector"].append({
                    "name": full_address,
                    "enable": values.get("enable", False),
                    "finding_publishing_frequency": values.get("finding_publishing_frequency"),
                    "__metadata": metadata
                })

            # --- AWS Config Recorder ---
            elif r_type == "aws_config_configuration_recorder":
                recording_group = values.get("recording_group", [])
                inventory["config_recorder"].append({
                    "name": values.get("name", full_address),
                    "recording_group": {
                        "all_supported": _get_val(recording_group, "all_supported", False),
                        "include_global_resource_types": _get_val(recording_group, "include_global_resource_types", False),
                    },
                    "__metadata": metadata
                })

            # --- AWS EKS Cluster ---
            elif r_type == "aws_eks_cluster":
                encryption_config = values.get("encryption_config", [])
                secrets_encrypted = False
                if isinstance(encryption_config, list):
                    for ec in encryption_config:
                        resources = ec.get("resources", [])
                        if "secrets" in resources:
                            secrets_encrypted = True
                elif isinstance(encryption_config, dict):
                    if "secrets" in encryption_config.get("resources", []):
                        secrets_encrypted = True

                endpoint_public = values.get("vpc_config", [{}])
                public_access = True
                if isinstance(endpoint_public, list) and len(endpoint_public) > 0:
                    public_access = endpoint_public[0].get("endpoint_public_access", True)
                elif isinstance(endpoint_public, dict):
                    public_access = endpoint_public.get("endpoint_public_access", True)

                inventory["eks_cluster"].append({
                    "name": values.get("name", full_address),
                    "endpoint_public_access": public_access,
                    "secrets_encrypted": secrets_encrypted,
                    "logging": values.get("enabled_cluster_log_types", []),
                    "__metadata": metadata
                })

            # --- AWS Secrets Manager Secret ---
            elif r_type == "aws_secretsmanager_secret":
                rotation_rules = values.get("rotation_rules", [])
                auto_rotation = False
                rotation_days = 0
                if isinstance(rotation_rules, list) and len(rotation_rules) > 0:
                    auto_rotation = True
                    rotation_days = rotation_rules[0].get("automatically_after_days", 0)
                elif isinstance(rotation_rules, dict):
                    auto_rotation = True
                    rotation_days = rotation_rules.get("automatically_after_days", 0)

                inventory["secrets_manager_secret"].append({
                    "name": values.get("name", full_address),
                    "kms_key_id": values.get("kms_key_id"),
                    "auto_rotation_enabled": auto_rotation,
                    "rotation_interval_days": rotation_days,
                    "__metadata": metadata
                })

            # --- AWS SNS Topic ---
            elif r_type == "aws_sns_topic":
                inventory["sns_topic"].append({
                    "name": values.get("name", full_address),
                    "kms_master_key_id": values.get("kms_master_key_id"),
                    "encrypted": bool(values.get("kms_master_key_id")),
                    "__metadata": metadata
                })

            # --- AWS SQS Queue ---
            elif r_type == "aws_sqs_queue":
                inventory["sqs_queue"].append({
                    "name": values.get("name", full_address),
                    "kms_master_key_id": values.get("kms_master_key_id"),
                    "encrypted": bool(values.get("kms_master_key_id")),
                    "__metadata": metadata
                })

            # --- AWS Lambda Function ---
            elif r_type == "aws_lambda_function":
                inventory["lambda_function"].append({
                    "name": values.get("function_name", full_address),
                    "runtime": values.get("runtime"),
                    "kms_key_arn": values.get("kms_key_arn"),
                    "tracing_config": values.get("tracing_config", {}),
                    "__metadata": metadata
                })

            # --- Azure PostgreSQL Server ---
            elif r_type == "azurerm_postgresql_server":
                inventory["azure_postgresql_server"].append({
                    "name": values.get("name", full_address),
                    "ssl_enforcement_enabled": values.get("ssl_enforcement_enabled", False),
                    "public_network_access_enabled": values.get("public_network_access_enabled", True),
                    "geo_redundant_backup_enabled": values.get("geo_redundant_backup_enabled", False),
                    "infrastructure_encryption_enabled": values.get("infrastructure_encryption_enabled", False),
                    "__metadata": metadata
                })

            # --- Azure MySQL Server ---
            elif r_type == "azurerm_mysql_server":
                inventory["azure_mysql_server"].append({
                    "name": values.get("name", full_address),
                    "ssl_enforcement_enabled": values.get("ssl_enforcement_enabled", False),
                    "public_network_access_enabled": values.get("public_network_access_enabled", True),
                    "__metadata": metadata
                })

            # --- Azure Container Registry ---
            elif r_type == "azurerm_container_registry":
                inventory["azure_container_registry"].append({
                    "name": values.get("name", full_address),
                    "admin_enabled": values.get("admin_enabled", False),
                    "sku": values.get("sku", "Basic"),
                    "public_network_access_enabled": values.get("public_network_access_enabled", True),
                    "__metadata": metadata
                })

            # --- Azure Log Analytics Workspace ---
            elif r_type == "azurerm_log_analytics_workspace":
                inventory["azure_log_analytics_workspace"].append({
                    "name": values.get("name", full_address),
                    "retention_in_days": values.get("retention_in_days", 30),
                    "sku": values.get("sku", "PerGB2018"),
                    "__metadata": metadata
                })

            # --- Azure Managed Disk ---
            elif r_type == "azurerm_managed_disk":
                inventory["azure_managed_disk"].append({
                    "name": values.get("name", full_address),
                    "encryption_type": values.get("encryption_settings", {}).get("enabled", False),
                    "disk_encryption_set_id": values.get("disk_encryption_set_id"),
                    "__metadata": metadata
                })

            # --- Azure Function App ---
            elif r_type in ["azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app"]:
                site_config = values.get("site_config", [])
                https_only = values.get("https_only", False)
                min_tls = "1.2"
                if isinstance(site_config, list) and len(site_config) > 0:
                    min_tls = site_config[0].get("min_tls_version", "1.2")
                elif isinstance(site_config, dict):
                    min_tls = site_config.get("min_tls_version", "1.2")
                inventory["azure_function"].append({
                    "name": values.get("name", full_address),
                    "https_only": https_only,
                    "site_config": {"min_tls_version": min_tls},
                    "__metadata": metadata
                })

            # --- GCP Logging Sink ---
            elif r_type == "google_logging_project_sink":
                inventory["logging_sink"].append({
                    "name": values.get("name", full_address),
                    "destination": values.get("destination", ""),
                    "filter": values.get("filter", ""),
                    "__metadata": metadata
                })

            # --- GCP VPC Network ---
            elif r_type == "google_compute_network":
                inventory["vpc_network"].append({
                    "name": values.get("name", full_address),
                    "auto_create_subnetworks": values.get("auto_create_subnetworks", True),
                    "routing_mode": values.get("routing_mode", "REGIONAL"),
                    "__metadata": metadata
                })

            elif r_type.startswith("aws_iam_") and (r_type.endswith("_policy") or r_type.endswith("_policy_attachment") or r_type.endswith("_role_policy")):
                res["values"]["__address"] = full_address
                iam_resources.append(res)

            # ====================== CRITICAL-CHECKS COVERAGE EXTENSIONS ======================

            # --- AWS API Gateway REST API ---
            elif r_type == "aws_api_gateway_rest_api":
                policy = values.get("policy") or ""
                inventory["apigateway_rest_api"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "endpoint_type": (values.get("endpoint_configuration", [{}]) or [{}])[0].get("types", ["EDGE"]),
                    "has_resource_policy": bool(policy),
                    "policy_blocks_anonymous": "deny" in str(policy).lower() and "anonymous" in str(policy).lower(),
                    "__metadata": metadata,
                })

            elif r_type == "aws_api_gateway_stage":
                inventory["apigateway_rest_api"].append({
                    "name": values.get("stage_name", full_address),
                    "id": full_address,
                    "xray_enabled": values.get("xray_tracing_enabled", False),
                    "logging_enabled": bool((values.get("access_log_settings") or [None])[0]),
                    "cache_encrypted": values.get("cache_cluster_enabled", False),
                    "__metadata": metadata,
                })

            # --- AWS WAFv2 ---
            elif r_type == "aws_wafv2_web_acl":
                inventory["wafv2_web_acl"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "scope": values.get("scope", "REGIONAL"),
                    "default_action_block": "block" in str(values.get("default_action", "")).lower(),
                    "__metadata": metadata,
                })

            # --- AWS ECS task definition ---
            elif r_type == "aws_ecs_task_definition":
                containers_raw = values.get("container_definitions") or "[]"
                try:
                    import json as _json
                    containers = _json.loads(containers_raw) if isinstance(containers_raw, str) else containers_raw
                except Exception:
                    containers = []
                privileged = any(c.get("privileged") for c in containers if isinstance(c, dict))
                root_user = any(not c.get("user") or c.get("user") == "root" for c in containers if isinstance(c, dict))
                inventory["ecs_task_definition"].append({
                    "name": values.get("family", full_address),
                    "id": full_address,
                    "privileged_container": privileged,
                    "runs_as_root": root_user,
                    "execution_role_set": bool(values.get("execution_role_arn")),
                    "task_role_set": bool(values.get("task_role_arn")),
                    "__metadata": metadata,
                })

            # --- AWS ECR ---
            elif r_type == "aws_ecr_repository":
                scanning = (values.get("image_scanning_configuration") or [{}])[0]
                inventory["ecr_repository"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "scan_on_push": scanning.get("scan_on_push", False),
                    "image_tag_mutability_immutable": values.get("image_tag_mutability", "MUTABLE") == "IMMUTABLE",
                    "encryption_kms": (values.get("encryption_configuration") or [{}])[0].get("encryption_type") == "KMS",
                    "__metadata": metadata,
                })

            # --- AWS OpenSearch ---
            elif r_type in ("aws_opensearch_domain", "aws_elasticsearch_domain"):
                advanced = values.get("advanced_security_options", [{}])
                if isinstance(advanced, list) and advanced:
                    advanced = advanced[0]
                else:
                    advanced = {}
                node_to_node = values.get("node_to_node_encryption", [{}])
                if isinstance(node_to_node, list) and node_to_node:
                    node_to_node = node_to_node[0]
                else:
                    node_to_node = {}
                ear = values.get("encrypt_at_rest", [{}])
                if isinstance(ear, list) and ear:
                    ear = ear[0]
                else:
                    ear = {}
                inventory["opensearch_domain"].append({
                    "name": values.get("domain_name", full_address),
                    "id": full_address,
                    "encrypted_at_rest": ear.get("enabled", False),
                    "node_to_node_encryption": node_to_node.get("enabled", False),
                    "fine_grained_access_control": advanced.get("enabled", False),
                    "https_enforced": (values.get("domain_endpoint_options") or [{}])[0].get("enforce_https", False),
                    "__metadata": metadata,
                })

            # --- AWS CloudFront ---
            elif r_type == "aws_cloudfront_distribution":
                viewer = values.get("viewer_certificate", [{}])
                if isinstance(viewer, list) and viewer:
                    viewer = viewer[0]
                else:
                    viewer = {}
                logging = values.get("logging_config", [{}])
                if isinstance(logging, list) and logging:
                    logging = logging[0]
                else:
                    logging = {}
                default_cb = values.get("default_cache_behavior", [{}])
                if isinstance(default_cb, list) and default_cb:
                    default_cb = default_cb[0]
                else:
                    default_cb = {}
                inventory["cloudfront_distribution"].append({
                    "name": values.get("comment", full_address),
                    "id": full_address,
                    "https_only": default_cb.get("viewer_protocol_policy") in ("redirect-to-https", "https-only"),
                    "logging_enabled": bool(logging.get("bucket")),
                    "minimum_tls_version_numeric": _tls_to_number(viewer.get("minimum_protocol_version", "TLSv1")),
                    "waf_attached": bool(values.get("web_acl_id")),
                    "__metadata": metadata,
                })

            # --- Azure AKS ---
            elif r_type == "azurerm_kubernetes_cluster":
                role_based = values.get("role_based_access_control_enabled", values.get("rbac_enabled", True))
                network_profile = (values.get("network_profile") or [{}])[0] if isinstance(values.get("network_profile"), list) else (values.get("network_profile") or {})
                inventory["azure_kubernetes_cluster"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "rbac_enabled": role_based,
                    "private_cluster_enabled": values.get("private_cluster_enabled", False),
                    "network_policy_set": bool(network_profile.get("network_policy")),
                    "azure_active_directory_integrated": bool(values.get("azure_active_directory_role_based_access_control")),
                    "__metadata": metadata,
                })

            # --- Azure Cosmos DB ---
            elif r_type == "azurerm_cosmosdb_account":
                inventory["azure_cosmosdb_account"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "public_network_access_disabled": values.get("public_network_access_enabled", True) is False,
                    "tls_min_version_numeric": _tls_to_number(values.get("minimal_tls_version", "Tls12")),
                    "local_auth_disabled": values.get("local_authentication_disabled", False),
                    "__metadata": metadata,
                })

            # --- Azure Redis ---
            elif r_type == "azurerm_redis_cache":
                inventory["azure_redis_cache"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "ssl_only": values.get("enable_non_ssl_port", False) is False,
                    "tls_min_version_numeric": _tls_to_number(values.get("minimum_tls_version", "1.0")),
                    "public_network_access_disabled": values.get("public_network_access_enabled", True) is False,
                    "__metadata": metadata,
                })

            # --- Azure role assignment (privilege grant) ---
            elif r_type == "azurerm_role_assignment":
                inventory["azure_role_assignment"].append({
                    "name": values.get("role_definition_name") or values.get("role_definition_id") or full_address,
                    "id": full_address,
                    "principal_id": values.get("principal_id"),
                    "scope": values.get("scope"),
                    "is_owner": "owner" in str(values.get("role_definition_name", "")).lower(),
                    "is_contributor": "contributor" in str(values.get("role_definition_name", "")).lower(),
                    "__metadata": metadata,
                })

            # --- GCP Cloud Run ---
            elif r_type in ("google_cloud_run_service", "google_cloud_run_v2_service"):
                # Public access manifests as IAM binding allUsers; here flag the service ingress
                template = (values.get("template") or [{}])[0] if isinstance(values.get("template"), list) else (values.get("template") or {})
                inventory["gcp_cloud_run_service"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "ingress": values.get("ingress", "all"),
                    "ingress_internal_only": values.get("ingress") in ("internal", "internal-and-cloud-load-balancing"),
                    "service_account_set": bool(template.get("service_account") or template.get("spec", [{}])[0].get("service_account_name") if isinstance(template.get("spec"), list) else None),
                    "__metadata": metadata,
                })

            # --- GCP Cloud Functions ---
            elif r_type in ("google_cloudfunctions_function", "google_cloudfunctions2_function"):
                inventory["gcp_cloudfunctions_function"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "ingress_settings_internal_only": values.get("ingress_settings") in ("ALLOW_INTERNAL_ONLY", "ALLOW_INTERNAL_AND_GCLB"),
                    "vpc_connector_set": bool(values.get("vpc_connector")),
                    "__metadata": metadata,
                })

            # --- GCP Secret Manager ---
            elif r_type == "google_secret_manager_secret":
                replication = values.get("replication", [{}])
                if isinstance(replication, list) and replication:
                    replication = replication[0]
                else:
                    replication = {}
                inventory["gcp_secret_manager_secret"].append({
                    "name": values.get("secret_id", full_address),
                    "id": full_address,
                    "user_managed_replication": "user_managed" in replication,
                    "rotation_configured": bool(values.get("rotation")),
                    "__metadata": metadata,
                })

            # --- GCP GKE deeper security config ---
            elif r_type == "google_container_cluster":
                workload_identity = (values.get("workload_identity_config") or [{}])[0] if isinstance(values.get("workload_identity_config"), list) else (values.get("workload_identity_config") or {})
                private_cluster = (values.get("private_cluster_config") or [{}])[0] if isinstance(values.get("private_cluster_config"), list) else (values.get("private_cluster_config") or {})
                master_auth = (values.get("master_auth") or [{}])[0] if isinstance(values.get("master_auth"), list) else (values.get("master_auth") or {})
                inventory["gke_cluster_security"].append({
                    "name": values.get("name", full_address),
                    "id": full_address,
                    "workload_identity_enabled": bool(workload_identity.get("workload_pool")),
                    "network_policy_enabled": bool((values.get("network_policy") or [{}])[0].get("enabled") if isinstance(values.get("network_policy"), list) else (values.get("network_policy") or {}).get("enabled")),
                    "private_nodes": private_cluster.get("enable_private_nodes", False),
                    "private_endpoint": private_cluster.get("enable_private_endpoint", False),
                    "shielded_nodes_enabled": (values.get("enable_shielded_nodes", False) or
                        (values.get("node_config", [{}])[0] if isinstance(values.get("node_config"), list) else (values.get("node_config") or {})).get("shielded_instance_config")),
                    "basic_auth_disabled": not bool(master_auth.get("username")),
                    "__metadata": metadata,
                })

        except Exception as e:
            logger.warning(f"Failed to normalize {res.get('address')}: {e}")

    # Process IAM Aggregation
    inventory["iam_policy"], member_roles = normalize_iam_members(iam_resources)
    
    # Post-process: Apply roles to synthesized Users/ServiceAccounts
    
    # Case 1: Existing GCP Service Accounts in inventory
    for sa in inventory["iam_service_account"]:
        email = sa.get("email")
        if email:
            # Check mappings for "serviceAccount:{email}"
            roles = member_roles.get(f"serviceAccount:{email}", set())
            # Merge existing roles if any
            existing_roles = set(sa.get("roles", []))
            sa["roles"] = list(existing_roles.union(roles))
            
    # Case 2: Create synthetic users from bindings if not in inventory
    for member, roles in member_roles.items():
        if member.startswith("user:"):
             user_email = member.replace("user:", "")
             # Check if already present
             found = False
             for u in inventory["iam_user"]:
                 if u.get("email") == user_email or u.get("name") == user_email:
                     u["roles"] = list(set(u.get("roles", [])).union(roles))
                     found = True
                     break
             
             if not found:
                 inventory["iam_user"].append({
                     "name": user_email,
                     "email": user_email,
                     "roles": list(roles),
                     "__metadata": {
                         "source_file": "iam_binding_derived",
                         "line": 0,
                         "resource_id": member
                     }
                 })

        elif member.startswith("serviceAccount:"):
            sa_email = member.replace("serviceAccount:", "")
            # Check if exists
            found = False
            for s in inventory["iam_service_account"]:
                if s.get("email") == sa_email:
                    s["roles"] = list(set(s.get("roles", [])).union(roles))
                    found = True
                    break
            
            if not found:
                 inventory["iam_service_account"].append({
                     "name": sa_email,
                     "email": sa_email,
                     "roles": list(roles),
                     "__metadata": {
                         "source_file": "iam_binding_derived",
                         "line": 0,
                         "resource_id": member
                     }
                 })
    
    return inventory
