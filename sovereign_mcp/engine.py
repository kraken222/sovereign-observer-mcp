"""Resolves the shared IaC engine, wherever this process happens to be running.

Two situations have to work:

*Installed wheel* — ``sovereign_mcp/_vendor`` was populated at build time by
``scripts/vendor_engine.py``. Import it and go.

*Source checkout* — ``_vendor`` is gitignored and absent on a fresh clone. We
vendor on demand from the backend tree next door, so a developer can clone and
run without a build step.

Both paths end at the same modules, which is the point: the MCP server and
``POST /api/iac/scan-pr`` must never disagree about whether a resource is
insecure. ``tests/test_parity.py`` is what actually holds that line.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_PKG_DIR = Path(__file__).resolve().parent
_VENDOR_DIR = _PKG_DIR / "_vendor"


class EngineUnavailable(RuntimeError):
    """The IaC engine could not be loaded or is missing a dependency."""


def _ensure_vendored() -> None:
    """Populate ``_vendor`` from the backend tree if it is not already there."""
    if (_VENDOR_DIR / "scanners" / "checkov_scanner.py").is_file():
        return

    scripts_dir = _PKG_DIR.parent / "scripts"
    if not (scripts_dir / "vendor_engine.py").is_file():
        raise EngineUnavailable(
            "sovereign_mcp/_vendor is missing and the vendoring script is not "
            "available. This build is incomplete — reinstall sovereign-mcp."
        )

    sys.path.insert(0, str(scripts_dir))
    try:
        import vendor_engine  # type: ignore[import-not-found]

        vendor_engine.vendor(dest=_VENDOR_DIR)
    except FileNotFoundError as exc:
        raise EngineUnavailable(
            f"Could not vendor the IaC engine from the backend source tree: {exc}"
        ) from exc
    finally:
        sys.path.remove(str(scripts_dir))


def _load() -> Any:
    _ensure_vendored()
    try:
        from ._vendor.scanners import checkov_scanner  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - packaging failure
        raise EngineUnavailable(f"Could not import the IaC engine: {exc}") from exc
    return checkov_scanner


_module = None


def scanner_module() -> Any:
    """The vendored ``checkov_scanner`` module (loaded once, cached)."""
    global _module
    if _module is None:
        _module = _load()
    return _module


def checkov_scanner_cls() -> Any:
    """The ``CheckovScanner`` class itself."""
    return scanner_module().CheckovScanner


def require_checkov() -> None:
    """Raise a message a developer can act on when Checkov is not importable.

    Checkov is a hard dependency in ``pyproject.toml``, so this should only fire
    in a broken environment — but the failure mode without it is a silent empty
    scan, which is the worst possible outcome for a security tool.
    """
    if not checkov_scanner_cls().is_available():
        raise EngineUnavailable(
            "The Checkov engine is not importable in this interpreter. "
            "Reinstall with: uv tool install sovereign-mcp"
        )


def policy_engine():
    """The YAML rule engine, for evaluating an organization's custom policies.

    ``policy_engine`` imports ``remediation_registry`` by absolute name, so the
    vendor directory has to be importable as a top-level path. We add it to
    ``sys.path`` rather than rewriting the import, because rewriting it would
    make the vendored copy differ from its source and break the drift test that
    keeps the editor and the server evaluating identical rules.

    The names this exposes at top level (``policy_engine``,
    ``remediation_registry``, ``remediation_supplement``) are contained to this
    process, which exists only to serve MCP over stdio.
    """
    _ensure_vendored()
    vendor_path = str(_VENDOR_DIR)
    if vendor_path not in sys.path:
        sys.path.insert(0, vendor_path)
    try:
        import policy_engine as _pe  # type: ignore[import-not-found]

        from ._vendor.scanners import terraform_inventory
    except ImportError as exc:  # pragma: no cover - packaging failure
        raise EngineUnavailable(f"Could not import the policy engine: {exc}") from exc
    return _pe, terraform_inventory


def hcl_to_plan():
    """Raw ``.tf`` sources -> a minimal Terraform plan-JSON shape."""
    _ensure_vendored()
    from ._vendor.scanners import hcl_to_plan as _h2p

    return _h2p


def auto_fixable_checks() -> set:
    """Check ids whose fix is a safe, in-place, single-attribute change.

    Deliberately short and hand-verified against each check's source — see the
    comment block above ``_AUTO_FIXABLE_CHECKS`` in the engine. Do not widen it
    here; widen it there, with a test, or not at all.
    """
    return set(scanner_module()._AUTO_FIXABLE_CHECKS)


def auto_fix_attributes() -> dict:
    """``check_id -> (attribute, value)`` for the allowlisted in-place fixes."""
    return dict(scanner_module()._AUTO_FIX_ATTRIBUTE)


def auto_fix_rejections() -> dict:
    """``check_id -> why this fix is deliberately not applied mechanically``.

    The generic advisory wording ("adds new resources, or touches a shape where
    a mechanical edit can break a working config") is true of most held-back
    checks and wrong about some of them. Where the engine recorded a specific
    reason, say that instead — an assistant that knows *why* a fix is held back
    stops trying to synthesise one.
    """
    return dict(scanner_module()._AUTO_FIX_REJECTED)


def curated_terraform_fixes() -> dict:
    """``check_id -> {summary, terraform}`` paste-ready snippets."""
    return dict(scanner_module()._TERRAFORM_FIX_BY_CHECK_ID)
