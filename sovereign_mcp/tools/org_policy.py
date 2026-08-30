"""Organization policy — the paid half, and the point of the whole integration.

Two jobs, and the first matters more than the second.

**Before generation** (``requirements``): the assistant asks what rules apply to
a resource type and gets the organization's actual requirements — approved
regions, mandatory tags, required instance classes — *before* it writes the
Terraform. Catching a violation after generation is a scanner. Supplying the
constraints before generation is the product.

**After generation** (``evaluate``): the org's rules run against the produced
HCL locally, through the same YAML engine and the same inventory shape the
server uses, so an org rule means the same thing in the editor as it does in a
scan or in CI.

The rules arrive from the API; the Terraform is evaluated here. Nothing is
uploaded.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .. import org
from ..engine import EngineUnavailable, hcl_to_plan, policy_engine

_OPERATOR_WORDS = {
    "ge": "at least",
    "gt": "greater than",
    "le": "at most",
    "lt": "less than",
    "eq": "exactly",
    "ne": "not",
}


def describe_condition(condition: Optional[Dict[str, Any]]) -> str:
    """Render a rule condition as a requirement a model can act on.

    The AI needs "set `retention_in_days` to at least 365", not a serialized
    condition object. This is what turns a policy database into generation
    guidance.
    """
    if not isinstance(condition, dict):
        return "See the policy definition."

    kind = condition.get("type")
    expression = condition.get("expression") or {}
    attribute = expression.get("attribute")

    if kind == "manual":
        return (
            "Requires human review — this control cannot be verified from "
            "Terraform alone."
        )
    if kind == "boolean":
        return f"`{attribute}` must be `{str(expression.get('value')).lower()}`."
    if kind == "comparison":
        word = _OPERATOR_WORDS.get(expression.get("operator"), expression.get("operator"))
        return f"`{attribute}` must be {word} {expression.get('value')}."
    if kind == "regex":
        return f"`{attribute}` must match `{expression.get('pattern')}`."
    if kind == "negative_regex":
        return f"`{attribute}` must NOT match `{expression.get('pattern')}`."
    if kind == "list_contains":
        return f"`{attribute}` must contain `{expression.get('value')}`."
    if kind == "list_match_any":
        allowed = expression.get("value") or []
        return f"`{attribute}` must be one of: {', '.join(map(str, allowed))}."
    if kind == "list_forbidden_match":
        key = expression.get("key")
        target = f"`{attribute}[].{key}`" if key else f"`{attribute}`"
        return f"No entry in {target} may be `{expression.get('pattern')}`."
    return "See the policy definition."


def requirements(
    resource_type: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    """The org's rules for a resource type, phrased as requirements.

    Called *before* the assistant writes Terraform.
    """
    if not org.is_connected():
        return {
            "connected": False,
            "requirements": [],
            "note": (
                "No organization policy is configured — this install is running "
                "the built-in rules locally only. Generate as normal and call "
                "scan_terraform afterwards. To apply your company's own rules, "
                "set SOVEREIGN_TOKEN from Integrations in the dashboard."
            ),
        }

    try:
        found = org.rules(provider=provider)
    except org.OrgPolicyError as exc:
        return {
            "connected": False,
            "error": str(exc),
            "requirements": [],
            "note": "Built-in rules still apply. Continue and scan as normal.",
        }

    wanted = (resource_type or "").strip().lower()
    if wanted:
        # Match generously: an org rule on `aws_db_instance` should surface for
        # a question about `db_instance`, and vice versa.
        matched = [
            rule for rule in found
            if _matches_resource(rule.get("resource_type"), wanted)
        ]
    else:
        matched = list(found)

    status = org.status()
    payload: Dict[str, Any] = {
        "connected": True,
        "org_name": status.get("org_name"),
        "resource_type": resource_type,
        "requirements": [
            {
                "id": rule.get("id"),
                "title": rule.get("title"),
                "severity": rule.get("severity"),
                "resource_type": rule.get("resource_type"),
                "requirement": describe_condition(rule.get("condition")),
                "policy": rule.get("policy_name"),
            }
            for rule in matched
        ],
        "total_org_rules": len(found),
    }

    if matched:
        payload["next_step"] = (
            "Generate the Terraform so it satisfies every requirement above, "
            "then call scan_terraform to confirm."
        )
    else:
        payload["note"] = (
            f"Your organization has {len(found)} custom rules, none scoped to "
            f"'{resource_type}'. Generate as normal, then scan."
            if wanted else "Your organization has no custom rules configured."
        )
    return payload


def connection_status() -> Dict[str, Any]:
    """Whether org policy is in force, and which rules that means."""
    return org.status()


_INVENTORY_KEY_CACHE: Dict[str, Optional[str]] = {}


def inventory_key_for(terraform_type: str) -> Optional[str]:
    """Map a Terraform resource type to the inventory key rules are written against.

    Policy rules key off inventory names (``rds_instance``), but a developer or
    an assistant asks about Terraform names (``aws_db_instance``). The two are
    related by a 59-branch mapping inside ``terraform_inventory``, which is a
    code path rather than a table.

    So instead of copying that table — and letting it drift the first time
    someone adds a resource type — this pushes a synthetic one-resource plan
    through the real mapper and observes which bucket fills. Derived from the
    mapping itself, it cannot disagree with it.
    """
    key = (terraform_type or "").strip().lower()
    if not key:
        return None
    if key in _INVENTORY_KEY_CACHE:
        return _INVENTORY_KEY_CACHE[key]

    resolved: Optional[str] = None
    try:
        _engine, inventory_module = policy_engine()
        probe = {
            "planned_values": {
                "root_module": {
                    "resources": [{
                        "address": f"{key}.probe",
                        "mode": "managed",
                        "type": key,
                        "name": "probe",
                        "values": {},
                    }]
                }
            }
        }
        inventory = inventory_module.map_terraform_to_inventory(probe)
        for bucket, items in (inventory or {}).items():
            if items:
                resolved = bucket
                break
    except Exception:
        resolved = None

    _INVENTORY_KEY_CACHE[key] = resolved
    return resolved


def _matches_resource(rule_resource: Optional[str], wanted: str) -> bool:
    """True when a rule's resource_type refers to what the caller asked about.

    Accepts either vocabulary: the caller may name a Terraform type
    (``aws_db_instance``) or the inventory key rules use (``rds_instance``).
    """
    if not rule_resource:
        return False
    candidate = str(rule_resource).strip().lower()
    if candidate == wanted:
        return True

    mapped = inventory_key_for(wanted)
    if mapped and candidate == mapped:
        return True

    reverse = inventory_key_for(candidate)
    if reverse and reverse == wanted:
        return True

    return candidate in wanted or wanted in candidate


def evaluate(sources: Dict[str, str], provider: Optional[str] = None) -> List[Dict[str, Any]]:
    """Run the org's custom rules against HCL sources, locally.

    Returns findings in the same compact shape ``scan_terraform`` emits, tagged
    ``source: org_policy`` so a developer can tell a company rule from a
    built-in one — which matters, because the fix for a company rule is a
    conversation with their platform team, not a Checkov doc link.
    """
    if not sources or not org.is_connected():
        return []

    try:
        rules = org.rules(provider=provider)
    except org.OrgPolicyError:
        # Never fail a scan because policy could not be fetched. The built-in
        # rules are the floor and they already ran.
        return []

    # Manual controls have nothing to evaluate against Terraform.
    rules = [r for r in rules if (r.get("condition") or {}).get("type") != "manual"]
    if not rules:
        return []

    try:
        engine_module, inventory_module = policy_engine()
        plan_module = hcl_to_plan()
    except EngineUnavailable:
        return []

    try:
        plan = plan_module.parse_hcl_to_plan(sources)
        inventory = inventory_module.map_terraform_to_inventory(plan)
        engine = engine_module.PolicyEngine(rules)
        _compliant, failing = engine.evaluate(inventory, "editor")
    except Exception:
        # A malformed org rule must not take the whole scan down with it.
        return []

    findings = []
    for item in failing or []:
        findings.append({
            "check_id": item.get("cis_control") or item.get("id"),
            "severity": (item.get("severity") or "Medium").capitalize(),
            "title": item.get("title"),
            "why": f"Required by your organization's policy: {item.get('title')}",
            "file": None,
            "line": None,
            "resource": item.get("resource") or item.get("location"),
            "service": item.get("service"),
            "fix_available": False,
            "auto_fixable": False,
            "source": "org_policy",
        })
    return findings
