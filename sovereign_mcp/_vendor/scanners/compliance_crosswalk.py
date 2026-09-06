# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/compliance_crosswalk.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""Control-domain crosswalk — the pure half of ComplianceService.

``ComplianceService`` needs the database; this does not. Everything here is a
function of a finding's *text*, which means it runs anywhere — including inside
the MCP server on a developer's laptop, where there is no Flask app and no scan
history.

That is the reason this module exists as a separate file. Without it the MCP
would have to reimplement domain inference, and two implementations of "is this
finding about identity or about storage?" drift immediately.

``compliance_service`` imports from here and keeps its ORM-facing signatures, so
nothing downstream changed.
"""
from __future__ import annotations

from typing import Dict, List


# Domain -> the controls in each framework that a finding in that domain speaks
# to. Deliberately conservative: a misconfiguration is evidence about a control,
# not proof of compliance with it.
CROSSWALK_BY_DOMAIN = {
    'identity': [
        {'framework': 'SOC2', 'control': 'CC6.1'},
        {'framework': 'ISO27001', 'control': 'A.5.15'},
        {'framework': 'ISO27001', 'control': 'A.8.2'},
        {'framework': 'NIST', 'control': 'AC-2'},
        {'framework': 'NIST', 'control': 'IA-2'},
        {'framework': 'PCI', 'control': '7.2'},
        {'framework': 'PCI', 'control': '8.3'},
    ],
    'storage': [
        {'framework': 'SOC2', 'control': 'CC6.1'},
        {'framework': 'ISO27001', 'control': 'A.8.3'},
        {'framework': 'ISO27001', 'control': 'A.8.24'},
        {'framework': 'NIST', 'control': 'AC-3'},
        {'framework': 'NIST', 'control': 'SC-28'},
        {'framework': 'PCI', 'control': '3.4'},
    ],
    'logging': [
        {'framework': 'SOC2', 'control': 'CC7.2'},
        {'framework': 'ISO27001', 'control': 'A.8.15'},
        {'framework': 'NIST', 'control': 'AU-2'},
        {'framework': 'NIST', 'control': 'AU-12'},
        {'framework': 'PCI', 'control': '10.2'},
    ],
    'monitoring': [
        {'framework': 'SOC2', 'control': 'CC7.2'},
        {'framework': 'ISO27001', 'control': 'A.8.16'},
        {'framework': 'NIST', 'control': 'SI-4'},
        {'framework': 'PCI', 'control': '10.4'},
    ],
    'network': [
        {'framework': 'SOC2', 'control': 'CC6.6'},
        {'framework': 'ISO27001', 'control': 'A.8.20'},
        {'framework': 'ISO27001', 'control': 'A.8.22'},
        {'framework': 'NIST', 'control': 'SC-7'},
        {'framework': 'PCI', 'control': '1.3'},
    ],
    'database': [
        {'framework': 'SOC2', 'control': 'CC6.1'},
        {'framework': 'ISO27001', 'control': 'A.8.24'},
        {'framework': 'NIST', 'control': 'SC-28'},
        {'framework': 'PCI', 'control': '3.4'},
    ],
    'secrets': [
        {'framework': 'SOC2', 'control': 'CC6.1'},
        {'framework': 'ISO27001', 'control': 'A.5.17'},   # Authentication information
        {'framework': 'ISO27001', 'control': 'A.8.24'},   # Use of cryptography
        {'framework': 'NIST', 'control': 'IA-5'},         # Authenticator management
        {'framework': 'PCI', 'control': '8.3'},
    ],
    'configuration': [
        {'framework': 'SOC2', 'control': 'CC8.1'},
        {'framework': 'ISO27001', 'control': 'A.8.9'},
        {'framework': 'NIST', 'control': 'CM-2'},
        {'framework': 'NIST', 'control': 'CM-6'},
        {'framework': 'PCI', 'control': '2.2'},
    ],
}


# Ordered most-specific first — 'iam' before 'storage' matters, because an IAM
# policy on a bucket is an identity finding, not a storage one.
_DOMAIN_TOKENS = (
    # First, and deliberately narrow. A credential committed to source is an
    # authentication-material problem, not a storage or configuration one — but
    # widening these tokens (to 'secret' or 'password') would re-classify a
    # large number of existing findings, which is a separate decision.
    ('secrets', ['hard coded', 'hardcoded', 'hard-coded']),
    ('identity', ['iam', 'identity', 'mfa', 'root', 'user', 'role', 'policy',
                  'permission', 'owner', 'admin']),
    ('logging', ['cloudtrail', 'logging', 'log ', 'audit log', 'flow log']),
    ('monitoring', ['guardduty', 'security center', 'defender', 'monitor',
                    'alarm', 'alert']),
    ('network', ['security group', 'firewall', 'nsg', 'network',
                 'publicly accessible', '0.0.0.0', 'internet', 'ssh', 'rdp', 'port']),
    ('database', ['rds', 'sql', 'database', 'db instance', 'cloud sql']),
    ('storage', ['s3', 'bucket', 'blob', 'storage', 'encrypt', 'kms',
                 'key vault', 'disk', 'volume']),
    ('configuration', ['config', 'configuration', 'tag', 'backup', 'versioning',
                       'lifecycle']),
)

DEFAULT_DOMAIN = 'configuration'


def finding_text(*values) -> str:
    """The searchable blob domain inference and the regulatory overlays share.

    One string, built once, so a finding is never classified two different ways
    by two different callers.
    """
    return ' '.join(str(v or '').lower() for v in values)


def infer_control_domain(text: str) -> str:
    """Classify a finding into a control domain from its searchable text."""
    haystack = text or ''
    for domain, tokens in _DOMAIN_TOKENS:
        if any(token in haystack for token in tokens):
            return domain
    return DEFAULT_DOMAIN


def crosswalk_for_domain(domain: str) -> List[Dict[str, str]]:
    """SOC 2 / ISO 27001 / NIST / PCI controls for one domain."""
    return list(CROSSWALK_BY_DOMAIN.get((domain or '').strip().lower(), []))
