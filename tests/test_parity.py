"""The test that keeps this package honest.

The MCP server and ``POST /api/iac/scan-pr`` must never disagree about whether a
resource is insecure. A finding that shows up in the editor but not in CI (or
the reverse) destroys trust in both, and it is the single most likely way this
package makes the product worse.

The defence is that there is exactly one copy of the rule logic in git and the
MCP's copy is generated mechanically. These tests assert both halves of that:
the generated copy is byte-identical to its source, and the generated set is
complete enough to actually run.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import vendor_engine  # noqa: E402

PKG_DIR = Path(__file__).resolve().parents[1] / "sovereign_mcp"
VENDOR_DIR = PKG_DIR / "_vendor"
APP_ROOT = vendor_engine.find_app_root()

pytestmark = pytest.mark.skipif(
    APP_ROOT is None,
    reason="backend source tree not present (installed wheel); drift cannot be checked here",
)


def _strip_generated_header(text: str, src_rel: str) -> str:
    """Drop exactly the banner the vendoring script prepends — no more.

    Removing "leading comment lines" instead would also eat a source file's own
    shebang or licence header, and then this test would pass while comparing two
    different things.
    """
    header = vendor_engine._GENERATED_HEADER.format(source=src_rel)
    assert text.startswith(header), f"vendored file is missing its generated banner: {src_rel}"
    return text[len(header):]


@pytest.mark.parametrize("src_rel,dst_rel", sorted(vendor_engine.MODULES.items()))
def test_vendored_module_is_identical_to_backend_source(src_rel: str, dst_rel: str):
    """No hand-edits, no drift, no second implementation of the rules."""
    source = (APP_ROOT / src_rel).read_text(encoding="utf-8")
    vendored = (VENDOR_DIR / dst_rel).read_text(encoding="utf-8")

    assert _strip_generated_header(vendored, src_rel) == source, (
        f"{dst_rel} has drifted from {src_rel}. Never edit sovereign_mcp/_vendor — "
        f"edit the backend module and re-run scripts/vendor_engine.py."
    )


def test_vendored_tree_is_not_committed():
    """``_vendor`` is generated at build time; committing it creates a second
    copy of the rule logic in git, which is the exact failure this design avoids.
    """
    result = subprocess.run(
        ["git", "check-ignore", str(VENDOR_DIR)],
        cwd=str(APP_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "sovereign_mcp/_vendor is not gitignored — it must never be committed."
    )


def test_freshly_vendored_engine_produces_identical_findings(tmp_path):
    """Re-vendor from scratch and confirm the module list is complete.

    Runs in a subprocess so the freshly generated tree is imported cleanly
    rather than colliding with the already-imported package in this process.
    """
    fixture = Path(__file__).resolve().parent / "fixtures" / "vulnerable.tf"
    if not fixture.is_file():
        pytest.skip("demo fixture not available")

    from sovereign_mcp.tools.scan import run_scan

    packaged = run_scan(files={"main.tf": fixture.read_text(encoding="utf-8")})

    dest = tmp_path / "_vendor"
    vendor_engine.vendor(app_root=APP_ROOT, dest=dest)

    script = f"""
import json, sys
sys.path.insert(0, {str(tmp_path)!r})
from _vendor.scanners.checkov_scanner import CheckovScanner
res = CheckovScanner.analyze({{"main.tf": open({str(fixture)!r}, encoding="utf-8").read()}})
print(json.dumps(sorted(
    (f["check_id"], f["severity"], f["resource_address"]) for f in res["findings"]
)))
"""
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=600
    )
    assert proc.returncode == 0, f"fresh vendor tree failed to run:\n{proc.stderr}"

    fresh = json.loads(proc.stdout)
    packaged_keys = sorted(
        [f["check_id"], f["severity"], f["resource"]] for f in packaged["findings"]
    )
    # The packaged result is capped for context; compare the overlap.
    assert packaged_keys == [list(t) for t in fresh][: len(packaged_keys)]


def test_checkov_pin_matches_the_backend():
    """Same engine version as the backend, or the two can legitimately differ."""
    pyproject = (PKG_DIR.parent / "pyproject.toml").read_text(encoding="utf-8")
    backend_reqs = (APP_ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")

    backend_pin = next(
        line.split("#")[0].strip()
        for line in backend_reqs.splitlines()
        if line.strip().startswith("checkov==")
    )
    assert backend_pin in pyproject, (
        f"backend pins {backend_pin} but the MCP package does not. "
        "Different engine versions mean the editor and CI can disagree."
    )
