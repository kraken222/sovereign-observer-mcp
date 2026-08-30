# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from policy_engine.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
import yaml
import logging
import re
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

from remediation_registry import REMEDIATIONS

def format_entry(rule_id, title, status, location, severity, service, 
                 cis_control="", project_name="", evidence="", remediation_url="", resource="", remediation=None):
    """Format a compliance finding entry"""
    finding = {
        "cis_control": rule_id,
        "title": title,
        "status": status,
        "location": location,
        "severity": severity,
        "service": service,
        "project": project_name,
        "evidence": evidence,
        "solution_doc": remediation_url,
        "resource": resource
    }
    if remediation:
        finding["remediation"] = remediation
    return finding

class RuleLoader:
    """Load CIS rules from YAML files"""
    
    def __init__(self, rules_file: str = "gcp_cis_rules.yaml"):
        self.rules_file = rules_file
    
    def load_rules(self) -> List[Dict[str, Any]]:
        try:
            with open(self.rules_file, 'r') as f:
                rules = yaml.safe_load(f)
                logger.info(f"Loaded {len(rules)} rules from {self.rules_file}")
                return rules
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return []

class PolicyEngine:
    """
    Strict CIS Policy Engine v4.0.0
    Decoupled from inventory logic.
    """
    
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def _get_attribute(self, target: Any, attribute: str) -> Any:
        if not attribute: return None
        val = target
        for part in attribute.split('.'):
            if isinstance(val, dict):
                val = val.get(part)
            elif hasattr(val, part):
                val = getattr(val, part)
            else:
                return None
        return val

    def evaluate(self, inventory: Dict[str, Any], project_name: str) -> tuple:
        findings_map = {} # match_key -> finding
        
        for rule in self.rules:
            resource_type = rule.get('resource_type')
            
            # Dynamic resource type resolution
            # Collectors use resource_type as the inventory key directly
            targets = inventory.get(resource_type, [])
            
            condition = rule.get('condition')
            if not condition: 
                continue

            for target in targets:
                # Resource identification
                res_name = target.get('name', 'Unknown')
                
                status, evidence = self._evaluate_condition(condition, target)
                
                # Deterministic Match Key for De-duplication
                match_key = f"{res_name}|{rule['id']}"
                
                # Fetch Remediation if Failed
                remediation_data = None
                if status is False:
                    remediation_data = REMEDIATIONS.get(rule['id'])
                
                final_status = "NON_COMPLIANT"
                if status is True:
                    final_status = "COMPLIANT"
                elif status is None:
                    final_status = "MANUAL_CHECK"

                finding = format_entry(
                    rule_id=rule['id'],
                    title=rule['title'],
                    status=final_status,
                    location=res_name, 
                    severity=rule['severity'],
                    service=rule['service'],
                    project_name=project_name,
                    evidence=evidence,
                    remediation_url=f"/api/solutions/{rule['id']}.md",
                    resource=res_name,
                    remediation=remediation_data
                )
                finding["match_key"] = match_key
                finding["solution_pdf"] = rule.get("solution_pdf")
                finding["framework_mappings"] = rule.get("framework_mappings", [])

                # Carry the resource's provider/terraform identity so downstream
                # consumers (e.g. the IaC PR scanner) can anchor a finding back
                # to its source declaration. Additive only — existing consumers
                # ignore these keys. ``resource_address`` is the Terraform address
                # (``aws_s3_bucket.data``) for IaC scans, or the cloud resource id
                # for runtime scans; falls back to the display name.
                # The Terraform inventory stores provider/source identity under
                # ``__metadata`` (resource_id = full TF address like
                # ``aws_s3_bucket.data``). Runtime collectors may instead use a
                # plain ``metadata`` dict. Prefer the former, fall back to the
                # latter, then to the display name.
                target_meta = None
                if isinstance(target, dict):
                    cand = target.get("__metadata")
                    if not isinstance(cand, dict):
                        cand = target.get("metadata")
                    if isinstance(cand, dict):
                        target_meta = cand
                if target_meta is not None:
                    finding["metadata"] = target_meta
                    finding["resource_address"] = target_meta.get("resource_id") or res_name
                else:
                    finding["resource_address"] = res_name

                # The condition's attribute (when present) tells us which
                # property failed — used to pinpoint the offending HCL line.
                cond_expr = condition.get("expression") if isinstance(condition, dict) else None
                if isinstance(cond_expr, dict) and cond_expr.get("attribute"):
                    finding["failed_attribute"] = cond_expr.get("attribute")

                # Add description from rule if available
                if rule.get('description'):
                    finding["description"] = rule['description']
                
                # PASS Suppression Logic
                if match_key in findings_map:
                    existing = findings_map[match_key]
                    if existing['status'] == 'NON_COMPLIANT':
                        continue
                    if status is False: 
                        findings_map[match_key] = finding
                else:
                    findings_map[match_key] = finding

        # Separate into compliant/non_compliant (AFTER all rules processed)
        compliant = []
        non_compliant = []
        
        for f in findings_map.values():
            if f['status'] == 'COMPLIANT':
                compliant.append(f)
            else:
                non_compliant.append(f)
                
        return compliant, non_compliant

    def _evaluate_condition(self, condition: Dict[str, Any], target: Any) -> tuple:
        """
        Evaluate a single declarative condition.
        Returns: (bool_success, str_evidence). 
        Returns None for success if Manual.
        """
        if not condition:
            return True, "No condition specified."
        
        c_type = condition.get('type')
        expr = condition.get('expression', {})
        
        val = self._get_attribute(target, expr.get('attribute'))
        
        if c_type == 'boolean':
             expected = expr.get('value', True)
             # Handle string-match comparisons (e.g., ssl_enforcement: "Enabled")
             if isinstance(expected, str) and expected.lower() not in ('true', 'false'):
                 result = str(val) == expected
                 return result, f"Expected '{expected}', found '{val}'"
             if isinstance(expected, str):
                 expected = expected.lower() == 'true'
             result = bool(val) == expected
             return result, f"Expected {expected}, found {val}"
             
        elif c_type == 'comparison':
            op = expr.get('operator') # eq, ne, gt, lt, ge, le
            ref = expr.get('value')
            if op == 'eq': return str(val) == str(ref), f"Value {val} == {ref}"
            if op == 'ne': return str(val) != str(ref), f"Value {val} != {ref}"
            try:
                v_f = float(val) if val is not None else 0
                r_f = float(ref)
                if op == 'gt': return v_f > r_f, f"Value {val} > {ref}"
                if op == 'lt': return v_f < r_f, f"Value {val} < {ref}"
                if op == 'ge': return v_f >= r_f, f"Value {val} >= {ref}"
                if op == 'le': return v_f <= r_f, f"Value {val} <= {ref}"
            except:
                pass
            return False, f"Comparison failed for {val} {op} {ref}"
            
        elif c_type == 'regex':
            pattern = expr.get('pattern')
            if val is None: return False, "Attribute not found"
            try:
                match = re.search(pattern, str(val))
                return bool(match), f"Pattern {pattern} in {val}"
            except Exception as e:
                return False, f"Regex error: {e}"

        elif c_type == 'negative_regex':
            pattern = expr.get('pattern')
            if val is None: return True, "Attribute not found (Compliant)"
            try:
                match = re.search(pattern, str(val))
                if match:
                    return False, f"Found forbidden pattern {pattern} in {val}"
                return True, f"Pattern {pattern} not found in {val}"
            except Exception as e:
                return False, f"Regex error: {e}"

        elif c_type == 'list_contains':
            target_val = expr.get('value')
            if isinstance(val, list):
                found = str(target_val) in [str(x) for x in val]
                return found, f"List contains {target_val}"
            return False, "Not a list"

        elif c_type == 'list_match_any':
            allowed_values = expr.get('value') or []
            if val is None:
                return False, "Attribute not found"
            if isinstance(val, list):
                val_set = {str(x) for x in val}
                allow_set = {str(x) for x in allowed_values}
                matched = len(val_set.intersection(allow_set)) > 0
                return matched, f"At least one allowed value matched: {matched}"
            matched = str(val) in [str(x) for x in allowed_values]
            return matched, f"Value {val} present in allowed list"

        elif c_type == 'list_match':
            expected_list = expr.get('value') or []
            if not isinstance(val, list):
                return False, "Not a list"
            actual = [str(x) for x in val]
            expected = [str(x) for x in expected_list]
            missing = [x for x in expected if x not in actual]
            return len(missing) == 0, f"Missing expected items: {missing}" if missing else "All expected items present"
            
        elif c_type == 'list_forbidden_match':
            pattern = expr.get('pattern')
            key = expr.get('key') 
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and key:
                        check_val = item.get(key)
                    else:
                        check_val = item
                    if check_val and re.search(pattern, str(check_val)):
                        return False, f"Found forbidden match {check_val}"
                return True, "No forbidden matches"
            return True, "Not a list"
            
        elif c_type == 'manual':
            return None, "Manual check required"
            
        return False, f"Unknown condition type {c_type}"
