"""``check_compliance`` — which regulatory controls these findings speak to.

This is the tool no other Terraform linter offers: DORA, NIS2, Saudi Arabia's
NCA Cloud Cybersecurity Controls and the UAE Information Assurance Standard,
mapped in the editor, alongside the usual SOC 2 / ISO 27001 / NIST / PCI
crosswalk.

The honesty constraints from the product carry over verbatim, because they are
what make the mapping worth anything:

* A mapping records which control a check **speaks to**. It is evidence for an
  assessment, not an attestation, not a certification, and not a pass.
* Every one of these regulations also carries governance, process, supply-chain
  and training obligations that no configuration scanner can observe. A clean
  scan is not a compliant organisation, and the tool must never imply it is.
* NCA control identifiers are provisional pending reconciliation against the
  authority's published catalogue. The subdomain names and mapping logic are
  stable; the numbers may move.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..engine import EngineUnavailable

_ATTESTATION_CAVEAT = (
    "These are control mappings, not a compliance assessment. Each entry records "
    "which control a failing check speaks to, which shortens evidence gathering "
    "for an audit. Every framework here also carries governance, process, "
    "supply-chain and training obligations that no configuration scanner can "
    "observe — a clean scan is not a compliant organisation."
)


def _overlays():
    from .._vendor.scanners import regulatory_overlays

    return regulatory_overlays


def _crosswalk():
    from .._vendor.scanners import compliance_crosswalk

    return compliance_crosswalk


def check_compliance(
    findings: Optional[List[Dict[str, Any]]] = None,
    files: Optional[Dict[str, str]] = None,
    frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Map findings to regulatory and audit-framework controls.

    Pass ``findings`` straight from ``scan_terraform``, or ``files`` to scan and
    map in one call.
    """
    # `findings=[]` and `findings=None` mean different things and must not be
    # collapsed: an explicit empty list is "I scanned, nothing failed", which
    # has to reach the "no gaps is not compliance" answer below. Only a caller
    # that supplied neither argument gets an error.
    if findings is None:
        if not files:
            return {
                "error": (
                    "Pass `findings` from scan_terraform, or `files` (filename -> "
                    "HCL) to scan and map in one call."
                )
            }
        from .scan import run_scan

        findings = run_scan(files=files).get("findings") or []

    if not findings:
        return {
            "frameworks": {},
            "findings_mapped": 0,
            "caveat": _ATTESTATION_CAVEAT,
            "note": (
                "No failing findings to map. That means these checks raised no "
                "evidence of a control gap — not that the frameworks are met."
            ),
        }

    try:
        overlays = _overlays()
        crosswalk = _crosswalk()
    except ImportError as exc:  # pragma: no cover - vendoring failure
        raise EngineUnavailable(f"Compliance mapping unavailable: {exc}") from exc

    wanted = {f.strip().upper() for f in frameworks} if frameworks else None
    mapped: Dict[str, Dict[str, Any]] = {}
    unmapped: List[str] = []

    for finding in findings:
        text = crosswalk.finding_text(
            finding.get("check_id"),
            finding.get("title"),
            finding.get("why"),
            finding.get("service"),
            finding.get("resource"),
        )
        domain = crosswalk.infer_control_domain(text)
        check_id = finding.get("check_id")
        hit = False

        # Regulatory overlays: DORA / NIS2 / NCA-CCC / NESA-IAS.
        for framework, controls in overlays.overlays_for(domain, text).items():
            if wanted and framework.upper() not in wanted:
                continue
            hit = True
            for control in sorted(controls):
                _record(mapped, framework, control, check_id, finding)

        # Audit crosswalk: SOC 2 / ISO 27001 / NIST / PCI.
        for entry in crosswalk.crosswalk_for_domain(domain):
            framework = entry["framework"]
            if wanted and framework.upper() not in wanted:
                continue
            hit = True
            _record(mapped, framework, entry["control"], check_id, finding)

        if not hit and check_id:
            unmapped.append(check_id)

    provisional = {f.upper() for f in overlays.PROVISIONAL_FRAMEWORKS}
    for framework, block in mapped.items():
        block["controls"] = dict(sorted(block["controls"].items()))
        block["controls_touched"] = len(block["controls"])
        if framework.upper() in provisional:
            block["provisional"] = True
            block["provisional_note"] = (
                "Control identifiers are provisional pending reconciliation with "
                "the authority's published catalogue. Subdomain names and the "
                "mapping logic are stable; the numbers may move. Cite the "
                "subdomain name rather than the number."
            )

    result: Dict[str, Any] = {
        "frameworks": dict(sorted(mapped.items())),
        "findings_mapped": len(findings) - len(unmapped),
        "caveat": _ATTESTATION_CAVEAT,
    }
    if unmapped:
        result["unmapped_checks"] = sorted(set(unmapped))
        result["unmapped_note"] = (
            "These checks have no defensible mapping to a control in the "
            "requested frameworks. They are omitted rather than guessed."
        )
    return result


def _record(
    mapped: Dict[str, Dict[str, Any]],
    framework: str,
    control: str,
    check_id: Optional[str],
    finding: Dict[str, Any],
) -> None:
    block = mapped.setdefault(framework, {"controls": {}})
    entry = block["controls"].setdefault(
        control, {"failing_checks": [], "resources": []}
    )
    if check_id and check_id not in entry["failing_checks"]:
        entry["failing_checks"].append(check_id)
    resource = finding.get("resource")
    if resource and resource not in entry["resources"]:
        entry["resources"].append(resource)


def coverage(framework: str) -> Dict[str, Any]:
    """Every article of a regulatory framework with its evidence status.

    Includes the articles automated scanning *cannot* evidence, which is the
    point — a coverage number is only meaningful next to what it excludes.
    """
    articles = _overlays().article_coverage(framework)
    if not articles:
        return {
            "error": f"'{framework}' is not a regulatory overlay.",
            "available": list(_overlays().REGULATORY_FRAMEWORKS),
        }

    evidenced = [a for a in articles if a["status"] != "not-evidenced"]
    return {
        "framework": framework.upper(),
        "articles": articles,
        "evidenced_count": len(evidenced),
        "total_count": len(articles),
        "caveat": _ATTESTATION_CAVEAT,
    }
