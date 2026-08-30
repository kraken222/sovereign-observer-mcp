#!/usr/bin/env python3
"""Copy the backend's IaC engine modules into ``sovereign_mcp/_vendor``.

Why this exists
---------------
The MCP server must run on a developer's laptop with no Flask app and no
network, but it must evaluate *exactly* the policy the backend evaluates. Two
hand-maintained copies of the rule logic would be worse than shipping no MCP at
all — a finding that appears in the editor but not in CI (or the reverse)
destroys trust in both.

So the backend stays the single source of truth in git, and this script
mechanically copies the modules at build time. ``sovereign_mcp/_vendor`` is
**generated and gitignored** — never edit it, and never commit it.

The copied modules are pure stdlib (verified: no Flask, no SQLAlchemy, no
``current_app``). The directory layout below mirrors the backend's
``services/`` + ``services/scanners/`` shape on purpose, so the relative import
``from ..remediation_service import RemediationService`` inside
``checkov_scanner`` keeps resolving without patching a single line.

Run directly (``python scripts/vendor_engine.py``) or let ``sovereign_mcp.engine``
call it automatically on first import in a source checkout.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Optional

# relpath under the backend  ->  relpath under _vendor/
MODULES = {
    "backend/app/services/remediation_service.py": "remediation_service.py",
    "backend/app/services/scanners/checkov_scanner.py": "scanners/checkov_scanner.py",
    "backend/app/services/scanners/hcl_locator.py": "scanners/hcl_locator.py",
    "backend/app/services/scanners/hcl_to_plan.py": "scanners/hcl_to_plan.py",
    "backend/app/services/scanners/regulatory_overlays.py": "scanners/regulatory_overlays.py",
    "backend/app/services/scanners/compliance_crosswalk.py": "scanners/compliance_crosswalk.py",
    # The HCL fix-applier the GitHub Action uses. Shared so a fix applied in the
    # editor is byte-for-byte the fix the Action would have applied in CI.
    "integrations/github-action/scan.py": "hcl_fixer.py",
    # Org custom-policy evaluation. These four run the same YAML rules against
    # the same inventory shape the server does, so an org rule means the same
    # thing in the editor as it does in a scan. They sit at the _vendor root
    # because policy_engine imports remediation_registry by absolute name.
    "backend/app/services/scanners/terraform_inventory.py": "scanners/terraform_inventory.py",
    "policy_engine.py": "policy_engine.py",
    "remediation_registry.py": "remediation_registry.py",
    "remediation_supplement.py": "remediation_supplement.py",
}

_GENERATED_HEADER = (
    "# ⚠ GENERATED FILE — DO NOT EDIT.\n"
    "# Copied verbatim from {source} by scripts/vendor_engine.py.\n"
    "# Edit the backend module instead; this copy is regenerated at build time.\n"
)


def find_app_root(start: Optional[Path] = None) -> Optional[Path]:
    """Walk up from ``start`` looking for the 'main application' directory.

    Returns None when running from an installed wheel, where there is no
    backend source tree to copy from (and none is needed — the wheel already
    carries the vendored modules).
    """
    here = (start or Path(__file__).resolve()).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "backend" / "app" / "services" / "scanners" / "checkov_scanner.py"
        if candidate.is_file():
            return parent
    return None


def vendor(app_root: Optional[Path] = None, dest: Optional[Path] = None) -> Path:
    """Copy the engine modules into ``dest``. Returns the vendor directory."""
    app_root = app_root or find_app_root()
    if app_root is None:
        raise FileNotFoundError(
            "Could not locate the backend source tree. Run this from a checkout "
            "of the Sovereign Observer repository."
        )

    dest = dest or (Path(__file__).resolve().parent.parent / "sovereign_mcp" / "_vendor")
    if dest.exists():
        shutil.rmtree(dest)
    (dest / "scanners").mkdir(parents=True, exist_ok=True)

    # Package markers so relative imports inside the copied modules resolve.
    (dest / "__init__.py").write_text(
        '"""Generated vendor tree — see scripts/vendor_engine.py."""\n', encoding="utf-8"
    )
    (dest / "scanners" / "__init__.py").write_text("", encoding="utf-8")

    for src_rel, dst_rel in MODULES.items():
        src = app_root / src_rel
        if not src.is_file():
            raise FileNotFoundError(f"Expected engine module missing: {src}")
        body = src.read_text(encoding="utf-8")
        (dest / dst_rel).write_text(
            _GENERATED_HEADER.format(source=src_rel) + body, encoding="utf-8"
        )

    return dest


def main() -> int:
    dest = vendor()
    print(f"vendored {len(MODULES)} engine modules -> {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
