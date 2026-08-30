"""``scan_terraform`` — the workhorse tool.

Output shape is the design decision that matters here. A real Terraform module
trips 20-60 Checkov policies, and each finding in the engine carries a full
remediation payload (summary, steps, CLI, Terraform snippet, doc links). Handing
all of that back would burn thousands of tokens of the assistant's context on a
single call and crowd out the code it is supposed to be writing.

So this returns one compact line per finding plus ``fix_available``, and the
depth lives behind ``explain_finding``. The assistant pulls detail only for the
findings it actually intends to act on.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..engine import checkov_scanner_cls, require_checkov

# Guardrails for the ``paths`` mode. The server runs on the developer's machine
# with their own permissions, so the risk is not access — it is someone pointing
# the tool at a monorepo root and waiting three minutes for a timeout.
MAX_FILES = 200
MAX_FILE_BYTES = 512 * 1024
MAX_FINDINGS_RETURNED = 25

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def collect_sources(
    files: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Build the ``relpath -> HCL`` mapping the engine expects.

    ``files`` (literal content) wins over ``paths`` (read from disk) so an
    assistant can scan an unsaved editor buffer — which is the whole point of
    scanning during generation rather than after commit.
    """
    if files:
        return {
            _norm(name): content
            for name, content in files.items()
            if isinstance(content, str) and content.strip()
        }

    collected: Dict[str, str] = {}
    for raw in paths or []:
        target = Path(raw).expanduser()
        if target.is_dir():
            candidates = sorted(target.rglob("*.tf"))
        elif target.is_file():
            candidates = [target]
        else:
            continue

        for tf in candidates:
            if len(collected) >= MAX_FILES:
                return collected
            try:
                if tf.stat().st_size > MAX_FILE_BYTES:
                    continue
                base = target if target.is_dir() else target.parent
                rel = os.path.relpath(tf, base)
                collected[_norm(rel)] = tf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

    return collected


def _norm(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def run_scan(
    files: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Scan Terraform sources and return a context-frugal result."""
    require_checkov()
    sources = collect_sources(files=files, paths=paths)

    if not sources:
        return {
            "scanned_files": 0,
            "findings_count": 0,
            "findings": [],
            "note": (
                "No Terraform sources were supplied. Pass `files` as a mapping of "
                "filename to HCL content (works on unsaved buffers), or `paths` as "
                "a list of .tf files or directories."
            ),
        }

    result = checkov_scanner_cls().analyze(sources)
    findings = [_compact(f) for f in (result.get("findings") or [])]

    # Organization rules, evaluated locally against the same sources. Returns
    # [] on a free (unconnected) install, so the local-only path is unchanged.
    from . import org_policy

    org_findings = org_policy.evaluate(sources, provider=result.get("provider"))
    findings.extend(org_findings)

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 99), f.get("file") or ""))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        bucket = (f.get("severity") or "Info").lower()
        counts[bucket if bucket in counts else "info"] += 1

    shown = findings[:MAX_FINDINGS_RETURNED]
    payload: Dict[str, Any] = {
        "scanned_files": len(sources),
        "provider": result.get("provider"),
        "policies_evaluated": (result.get("summary") or {}).get("passed", 0)
        + (result.get("summary") or {}).get("failed", 0),
        "findings_count": len(findings),
        "summary": counts,
        "findings": shown,
    }

    if org_findings:
        payload["org_policy_violations"] = len(org_findings)
        payload["org_policy_note"] = (
            "Findings tagged `source: org_policy` come from your organization's "
            "own rules, not the built-in set. They have no generic fix — satisfy "
            "the stated requirement, and call org_requirements for the details."
        )

    if len(findings) > len(shown):
        payload["truncated"] = True
        payload["note"] = (
            f"Showing the {len(shown)} most severe of {len(findings)} findings, "
            "ordered by severity. Fix these first, then re-scan."
        )

    payload["next_step"] = (
        "Call explain_finding(check_id) for the full remediation of any finding "
        "you intend to fix. Do not guess the fix — the exact Terraform is available."
    )
    return payload


def _compact(finding: Dict[str, Any]) -> Dict[str, Any]:
    """One finding, trimmed to what the assistant needs to decide and locate."""
    return {
        "check_id": finding.get("check_id"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "why": finding.get("remediation_summary") or finding.get("title"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "resource": finding.get("resource_address"),
        "service": finding.get("service"),
        # True when a concrete Terraform snippet exists for this check.
        "fix_available": bool(finding.get("remediation_terraform")),
        # True only for the hand-verified in-place single-attribute allowlist —
        # see apply_fix. A fix can be available without being auto-applyable.
        "auto_fixable": bool(finding.get("auto_fixable")),
        # Stated explicitly so a company rule is never mistaken for a built-in
        # one — they have different fixes and different people to argue with.
        "source": "builtin",
    }
