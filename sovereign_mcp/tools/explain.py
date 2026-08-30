"""``explain_finding`` — the depth behind ``scan_terraform``'s one-liners.

Resolution order, best source first:

1. The curated Checkov-keyed snippet (``_TERRAFORM_FIX_BY_CHECK_ID``). Written
   and verified per check id, and already interpolates the failing resource's
   local name so the snippet drops straight in.
2. The shared playbook library, matched on the check's human title. Same
   fallback the PR endpoint uses, so the editor and CI say the same thing.
3. Checkov's own imperative check name, which already states the fix in one
   line ("Ensure the S3 bucket has access logging enabled").

The auto-fix verdict is reported here too, including *why* a fix is advisory
when it is. "This one is not safe to apply mechanically" is a more useful answer
than silence, and it stops the assistant inventing a patch for a check the
engine deliberately holds back.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..engine import auto_fix_attributes, auto_fixable_checks, curated_terraform_fixes

DOCS_URL = "https://sovereign-observer.com"


def _local_name(resource_address: Optional[str]) -> str:
    if not resource_address:
        return "this"
    clean = str(resource_address).split("[")[0]
    parts = [p for p in clean.split(".") if p]
    return parts[-1] if parts else "this"


def explain(
    check_id: str,
    resource_address: Optional[str] = None,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    """Full remediation detail for one check id."""
    check_id = (check_id or "").strip()
    if not check_id:
        return {"error": "check_id is required, e.g. 'CKV_AWS_16'."}

    res = _local_name(resource_address)
    out: Dict[str, Any] = {"check_id": check_id, "resource": resource_address}

    curated = curated_terraform_fixes().get(check_id)
    if curated:
        out["summary"] = curated["summary"]
        out["terraform"] = curated["terraform"].format(res=res)
        out["source"] = "curated"
    else:
        playbook = _playbook(title or check_id, res)
        if playbook:
            out.update(playbook)
            out["source"] = "playbook"
        else:
            out["summary"] = title or check_id
            out["source"] = "check_name"
            out["note"] = (
                "No curated Terraform snippet exists for this check. The check "
                "name states the required end state; derive the attribute from "
                "the provider documentation rather than guessing."
            )

    auto = check_id in auto_fixable_checks()
    out["auto_fixable"] = auto
    if auto:
        attr = auto_fix_attributes().get(check_id)
        if attr:
            out["auto_fix"] = {"attribute": attr[0], "value": attr[1]}
        out["auto_fix_note"] = (
            "Safe to apply mechanically — a single in-place attribute change. "
            "Call apply_fix to get the patched HCL."
        )
    else:
        out["auto_fix_note"] = (
            "Advisory only. This fix either adds new resources or touches a "
            "resource shape where a mechanical edit can break a working "
            "configuration. Apply it by hand and review the diff."
        )

    out["learn_more"] = f"{DOCS_URL}/checks/{check_id.lower()}"
    return out


def _playbook(title: str, resource_local_name: str) -> Optional[Dict[str, Any]]:
    """Look up the shared playbook library, if it carries a concrete fix."""
    try:
        from .._vendor.remediation_service import RemediationService
    except ImportError:  # pragma: no cover - vendoring failure
        return None

    try:
        pb = RemediationService.get_playbook(
            title,
            resource_id=resource_local_name,
            provider="iac",
        )
    except Exception:
        return None

    # The library's generic fallback ("no exact playbook available" prose) reads
    # badly inline, so only adopt a playbook that carries something pasteable.
    if not pb or not (pb.get("terraform") or pb.get("cli")):
        return None

    out: Dict[str, Any] = {"summary": pb.get("summary") or pb.get("title") or title}
    for key in ("terraform", "cli", "steps", "rollback"):
        if pb.get(key):
            out[key] = pb[key]
    if pb.get("docs"):
        out["docs"] = pb["docs"]
    return out
