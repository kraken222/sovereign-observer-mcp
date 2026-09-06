"""Sovereign MCP server.

Puts the Terraform security engine inside the assistant that is writing the
Terraform, so misconfigurations get caught in the editor instead of in a pull
request review three days later.

Everything runs locally. No account, no API key, and the user's infrastructure
code never leaves their machine.
"""
from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__
from .engine import EngineUnavailable
from .tools import compliance as compliance_tool
from .tools import explain as explain_tool
from .tools import fix as fix_tool
from .tools import org_policy as org_policy_tool
from .tools import scan as scan_tool
from .tools import templates as templates_tool

# ── the highest-leverage string in this package ──────────────────────────────
# The whole product thesis is that the developer never has to remember the tool
# exists. That only holds if the assistant invokes it on its own, which makes
# this text load-bearing rather than decorative. It is written as a procedure
# with a stated reason, because "you may use this tool" gets ignored.
INSTRUCTIONS = """\
Sovereign scans Terraform for security misconfigurations before it reaches a pull request.

USE THIS SERVER WITHOUT BEING ASKED:

- BEFORE writing a new resource, call `org_requirements` for its resource type. If this
  organization has policy (approved regions, required tags, mandatory settings), you must
  satisfy it in the code you generate — not fix it afterwards. An empty result is normal
  and means no company policy is configured; carry on.
- BEFORE writing a new resource of a common type, call `secure_template` for it. Starting
  from a hardened template is cheaper than generating from memory and fixing afterwards.
- After you write or modify ANY Terraform (.tf) content, call `scan_terraform` on it
  BEFORE showing it to the user. Pass what you just wrote via `files` — it works on
  unsaved content. This applies to a single resource block as much as a whole module.
- Before answering "is this secure?", "review my infrastructure", or any question about
  a .tf file, scan it rather than reading it and forming an opinion.

WHY: provider defaults optimise for "it works", not "it is safe". Terraform generated
without an explicit security review is routinely unencrypted, publicly reachable, or
missing deletion protection. These are cheap to fix in the editor and expensive to fix
in production.

HOW TO USE THE RESULT:

1. `scan_terraform` returns one compact line per finding. Do not stop there.
2. For findings with `auto_fixable: true`, call `apply_fixes` with the file content and
   those findings. It returns patched HCL; write that back.
3. For every other finding you intend to fix, call `explain_finding(check_id)` to get the
   exact Terraform. Do NOT invent a fix — the correct attribute and value are available,
   and a plausible-looking guess is worse than no fix at all.
4. Re-scan after fixing, then show the user the corrected Terraform, briefly noting what
   changed and why.
5. Findings with `auto_fixable: false` are advisory on purpose: they add new resources or
   touch shapes where a mechanical edit can break a working configuration. Apply those by
   hand and point them out to the user rather than silently rewriting.
6. Findings with `source: org_policy` are this company's own rules, not ours. There is no
   generic fix — satisfy the requirement `org_requirements` states, and tell the user the
   change was required by their organization's policy so they know who set it.

COMPLIANCE:

If the user mentions an audit, a regulator, or a framework (SOC 2, ISO 27001, NIST, PCI,
DORA, NIS2, NCA, NESA), call `check_compliance` on the findings. Relay its caveat: these
are control mappings that shorten evidence gathering, not a compliance verdict. Never tell
a user they are compliant with anything.

Do not tell the user their Terraform is secure unless a scan returned zero findings.
"""

mcp = MCPServer(
    name="sovereign",
    title="Sovereign — Terraform security",
    version=__version__,
    instructions=INSTRUCTIONS,
    website_url="https://sovereign-observer.com",
)


@mcp.tool(
    title="Scan Terraform for security misconfigurations",
    description=(
        "Scan Terraform (HCL) for security misconfigurations and compliance failures. "
        "Call this after generating or editing any .tf content, before showing it to the "
        "user. Pass `files` (filename -> HCL content) to scan content that is not saved "
        "yet, or `paths` to scan .tf files and directories on disk. Runs locally; nothing "
        "is uploaded. Returns findings ordered by severity, each with a file, line, and "
        "whether an exact fix is available. Every finding is tagged with the environment "
        "it was inferred to belong to (production/staging/development/unknown). Set "
        "`environment_aware` to let resilience and housekeeping findings report lower on "
        "a non-production stack; exposure, encryption, identity and hardcoded credentials "
        "never move, in any environment."
    ),
)
def scan_terraform(
    files: dict[str, str] | None = None,
    paths: list[str] | None = None,
    environment_aware: bool = False,
) -> dict[str, Any]:
    try:
        return scan_tool.run_scan(
            files=files, paths=paths, environment_aware=environment_aware
        )
    except EngineUnavailable as exc:
        return {"error": str(exc)}


@mcp.tool(
    title="Explain a finding and get its exact fix",
    description=(
        "Get the full remediation for one finding from scan_terraform: what is wrong, the "
        "exact Terraform to fix it, and whether it is safe to apply mechanically. Call "
        "this for every finding you intend to fix instead of guessing the fix yourself."
    ),
)
def explain_finding(
    check_id: str,
    resource_address: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    try:
        return explain_tool.explain(
            check_id, resource_address=resource_address, title=title
        )
    except EngineUnavailable as exc:
        return {"error": str(exc)}


@mcp.tool(
    title="Apply the safe fixes to Terraform source",
    description=(
        "Apply the mechanically-safe fixes from scan_terraform to Terraform source and "
        "return the patched HCL. Pass the file content plus the findings you want fixed "
        "(each as {check_id, resource_address}). Only fixes on the hand-verified "
        "allowlist are applied; everything else is returned in `skipped` with the reason, "
        "and must be applied by hand. Never overwrites a value that is wired to a "
        "variable or expression. Returns content — it does not write to disk."
    ),
)
def apply_fixes(
    content: str,
    fixes: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        return fix_tool.apply_fixes(content=content, fixes=fixes)
    except EngineUnavailable as exc:
        return {"error": str(exc)}


@mcp.tool(
    title="Get a security-hardened starting template",
    description=(
        "Get a security-hardened Terraform template for a resource type (for example "
        "'aws_s3_bucket', 'aws_db_instance', 'aws_security_group', "
        "'azurerm_storage_account', 'google_storage_bucket'). Prefer this over writing "
        "the resource from memory: provider defaults are frequently insecure, and every "
        "template here is test-verified to contain no Critical or High findings. Returns "
        "the Terraform plus notes on what deliberately still needs the user's input."
    ),
)
def secure_template(resource_type: str) -> dict[str, Any]:
    return templates_tool.get_template(resource_type)


@mcp.tool(
    title="Map findings to compliance frameworks",
    description=(
        "Map Terraform findings to the compliance controls they speak to: SOC 2, "
        "ISO 27001, NIST 800-53, PCI-DSS, and the regulatory overlays DORA, NIS2, "
        "Saudi NCA Cloud Cybersecurity Controls and UAE NESA/SIA. Pass `findings` from "
        "scan_terraform, or `files` to scan and map in one call. Returns control "
        "mappings — evidence for an audit, never an attestation of compliance. Always "
        "relay the returned caveat to the user; do not present the result as a "
        "compliance verdict."
    ),
)
def check_compliance(
    findings: list[dict[str, Any]] | None = None,
    files: dict[str, str] | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    try:
        return compliance_tool.check_compliance(
            findings=findings, files=files, frameworks=frameworks
        )
    except EngineUnavailable as exc:
        return {"error": str(exc)}


@mcp.tool(
    title="Framework coverage, including what cannot be evidenced",
    description=(
        "For one regulatory framework (DORA, NIS2, NCA-CCC, NESA-IAS), list every "
        "article with whether automated configuration scanning can evidence it. Use "
        "this when the user asks how much of a regulation the tool covers — the "
        "not-evidenced articles are part of the honest answer and must be shown."
    ),
)
def framework_coverage(framework: str) -> dict[str, Any]:
    try:
        return compliance_tool.coverage(framework)
    except EngineUnavailable as exc:
        return {"error": str(exc)}


@mcp.tool(
    title="Get the organization's rules for a resource type",
    description=(
        "Get this organization's own infrastructure policy requirements for a resource "
        "type — approved regions, required tags, mandatory settings — BEFORE writing the "
        "Terraform. Call this first whenever you are about to create a resource, so the "
        "code satisfies company policy on the first attempt rather than being corrected "
        "afterwards. Returns an empty, explanatory result when no organization policy is "
        "configured, which is normal and not an error."
    ),
)
def org_requirements(
    resource_type: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    return org_policy_tool.requirements(resource_type=resource_type, provider=provider)


@mcp.tool(
    title="Check whether organization policy is connected",
    description=(
        "Report whether this install is applying an organization's custom policy or "
        "running built-in rules only, including the org name and rule count. Use it when "
        "the user asks which rules are in force, or why a company rule is not appearing."
    ),
)
def org_status() -> dict[str, Any]:
    return org_policy_tool.connection_status()


def main() -> None:
    """Console-script entry point (stdio transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
