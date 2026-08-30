"""``apply_fixes`` — turn findings into patched HCL.

The applier itself is the GitHub Action's ``apply_attribute_fix``, vendored
rather than reimplemented, so a fix applied in the editor is byte-for-byte the
fix the Action would have applied in CI.

Two constraints carry over from the Action and are not negotiable here:

*The allowlist stays closed.* Only checks in ``_AUTO_FIXABLE_CHECKS`` are
applied. That list is short because it was hand-verified against each check's
source — Checkov's registry metadata reports a default expected value of ``True``
for checks that never set one, which makes bulk-importing it actively dangerous.
``backend/tests/test_autofix_allowlist.py`` encodes that trap.

*Deliberate values are never clobbered.* If the attribute is already wired to a
variable or expression, the applier leaves it alone rather than overwriting a
human decision with a scanner verdict that may be wrong.

This returns patched content; it does not write files. The assistant already has
file-writing tools and the user can see the diff there — a security tool that
silently rewrites files on disk is a worse trade than one extra step.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..engine import auto_fix_attributes, auto_fixable_checks, scanner_module


def _applier():
    from .._vendor.hcl_fixer import apply_attribute_fix

    return apply_attribute_fix


def apply_fixes(
    content: str,
    fixes: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Apply every safe fix in ``fixes`` to ``content``.

    ``fixes`` is a list of ``{"check_id": ..., "resource_address": ...}`` taken
    straight from ``scan_terraform`` output.
    """
    if not isinstance(content, str) or not content.strip():
        return {"error": "content must be the Terraform source to patch."}
    if not fixes:
        return {"error": "fixes must be a non-empty list of {check_id, resource_address}."}

    allowlist = auto_fixable_checks()
    attributes = auto_fix_attributes()
    module = scanner_module()
    apply_attribute_fix = _applier()

    patched = content
    applied: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for item in fixes:
        check_id = (item or {}).get("check_id")
        address = (item or {}).get("resource_address")

        if check_id not in allowlist:
            skipped.append({
                "check_id": check_id,
                "resource_address": address,
                "reason": (
                    "Not on the auto-fix allowlist. This fix adds new resources or "
                    "touches a shape where a mechanical edit can break a working "
                    "configuration — call explain_finding and apply it by hand."
                ),
            })
            continue

        # Re-check the meta-loop guard against the content we are actually
        # editing. Checkov mis-evaluates dynamic/count/for_each resources, so a
        # fix there can be both syntactically clean and operationally wrong.
        if module.CheckovScanner._resource_uses_meta_loops({"f.tf": patched}, address):
            skipped.append({
                "check_id": check_id,
                "resource_address": address,
                "reason": (
                    "Resource uses dynamic/count/for_each — fix kept advisory to "
                    "avoid breaking a working configuration."
                ),
            })
            continue

        attr = attributes.get(check_id)
        if not attr:
            skipped.append({
                "check_id": check_id,
                "resource_address": address,
                "reason": "No structured attribute fix is registered for this check.",
            })
            continue

        new_content, changed = apply_attribute_fix(patched, address, attr[0], attr[1])
        if changed:
            patched = new_content
            applied.append({
                "check_id": check_id,
                "resource_address": address,
                "change": f"{attr[0]} = {attr[1]}",
            })
        else:
            skipped.append({
                "check_id": check_id,
                "resource_address": address,
                "reason": (
                    "No change made — the resource was not found, the value is "
                    "already correct, or the attribute is wired to a variable or "
                    "expression that must not be overwritten."
                ),
            })

    result: Dict[str, Any] = {
        "content": patched,
        "modified": patched != content,
        "applied": applied,
        "skipped": skipped,
    }
    if applied:
        result["next_step"] = (
            "Write this content back to the file, then call scan_terraform again "
            "to confirm the findings are cleared."
        )
    else:
        result["next_step"] = (
            "Nothing was applied. Use explain_finding for the exact Terraform and "
            "make the change by hand."
        )
    return result
