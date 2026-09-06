# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/regulatory_overlays.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""Regulatory overlays — DORA and NIS2 mapped onto checks we already run.

DORA (Regulation (EU) 2022/2554) and NIS2 (Directive (EU) 2022/2555) are not
scanners. Every control this module emits is already evidenced by a CIS-backed
check the product performs; the overlay only records which regulatory article
that check speaks to.

Why this is not another tier of ``CROSSWALK_BY_DOMAIN``
------------------------------------------------------
``ComplianceService._compliance_groups_for_finding`` resolves scanner metadata
in priority order, and every tier after the first is guarded by ``if not
groups``. Prowler stamps ``evidence.compliance`` on every runtime finding, and a
healthy runtime scan is Prowler-only — so the domain crosswalk is unreachable in
production. A regulatory mapping added there would be dead code. These overlays
are therefore merged *additively*, after and independent of scanner metadata.
``test_regulatory_overlays_are_additive_to_prowler_metadata`` fails if that ever
regresses.

Scope, and what ``status`` means
--------------------------------
Most of DORA Articles 5-15 and NIS2 Article 21(2) are governance, process and
supply-chain obligations that no configuration scanner can observe. Those
articles are declared here with ``not-evidenced`` and deliberately emit no
controls — an article scoring 100% because nothing was checked is a worse claim
than one we admit we cannot see.

  ``evidenced``     the article's technical core is directly observable here
  ``partial``       some clauses observable, the rest are process or out of scope
  ``not-evidenced`` nothing observable; entirely governance, process or people

``article_coverage()`` exposes the full article list with its status so the UI
and the PDF can show the evidenced ratio rather than a score computed over a
silently truncated denominator.

This is a control mapping. It is not a certification, an audit, or an
attestation of DORA or NIS2 compliance.
"""
from __future__ import annotations

from typing import Dict, List, Sequence, Set, Tuple

REGULATORY_FRAMEWORKS = ('DORA', 'NIS2', 'NCA-CCC', 'NESA-IAS')

# Frameworks whose *identifiers* have not been checked against the official
# published catalogue. The mapping semantics — which security topic each
# subdomain covers, and which of our checks evidence it — are sound; the
# numbering is reconstructed and may not match the authority's document.
#
# Consequence, and it is a hard rule: do not put these control numbers in front
# of a regulated customer or an auditor until someone has reconciled them
# against the source PDF. The subdomain names are safe to show. Correcting a
# number is a one-line change to the catalogue below — nothing else moves.
PROVISIONAL_FRAMEWORKS = ('NCA-CCC',)


def _dora(article: int) -> str:
    # Zero-padded so the matrix's lexical control sort keeps Art. 09 before
    # Art. 10 instead of ordering 10, 11, 12, 7, 8, 9.
    return f"Art. {article:02d}"


def _nis2(point: str) -> str:
    return f"Art. 21(2)({point})"


def _nca(domain: int, subdomain: int) -> str:
    # Zero-padded for the same reason as DORA: the matrix sorts control ids
    # lexically, and 2-1 / 2-10 / 2-2 is not an ordering anyone can read.
    return f"{domain}-{subdomain:02d}"


def _nesa(family: str) -> str:
    return family


# ── article catalogue ────────────────────────────────────────────────────────
# (label, subject, status). Statuses are self-consistent with what the mapping
# below can actually emit: nothing is declared evidenced or partial unless some
# domain or keyword rule assigns it a control.
_DORA_ARTICLES: Tuple[Tuple[str, str, str], ...] = (
    (_dora(5), 'Governance and organisation', 'not-evidenced'),
    (_dora(6), 'ICT risk management framework', 'not-evidenced'),
    (_dora(7), 'ICT systems, protocols and tools', 'partial'),
    (_dora(8), 'Identification', 'not-evidenced'),
    (_dora(9), 'Protection and prevention', 'evidenced'),
    (_dora(10), 'Detection', 'evidenced'),
    (_dora(11), 'Response and recovery', 'partial'),
    (_dora(12), 'Backup policies, restoration and recovery', 'evidenced'),
    (_dora(13), 'Learning and evolving', 'not-evidenced'),
    (_dora(14), 'Communication', 'not-evidenced'),
    (_dora(15), 'Further harmonisation of ICT risk management tools', 'not-evidenced'),
)

_NIS2_MEASURES: Tuple[Tuple[str, str, str], ...] = (
    (_nis2('a'), 'Risk analysis and information system security policies', 'not-evidenced'),
    (_nis2('b'), 'Incident handling', 'partial'),
    (_nis2('c'), 'Business continuity, backup management and disaster recovery', 'partial'),
    (_nis2('d'), 'Supply chain security', 'not-evidenced'),
    (_nis2('e'), 'Security in acquisition, development and maintenance; vulnerability handling', 'partial'),
    (_nis2('f'), 'Policies to assess the effectiveness of risk-management measures', 'not-evidenced'),
    (_nis2('g'), 'Basic cyber hygiene practices and training', 'not-evidenced'),
    (_nis2('h'), 'Cryptography and encryption', 'evidenced'),
    (_nis2('i'), 'Human resources security, access control and asset management', 'partial'),
    (_nis2('j'), 'Multi-factor authentication and secured communications', 'partial'),
)

# NCA Cloud Cybersecurity Controls (CCC-1:2020), Saudi Arabia — tenant side.
# CCC splits every control into a Cloud Service Provider (CSP) and a Cloud
# Service Tenant (CST) obligation. Our customer is the tenant: they run
# workloads in someone else's cloud. Mapping the CSP side would be claiming
# evidence about AWS's or Azure's own compliance, which we cannot see and which
# is not our customer's obligation anyway. Everything below is CST scope.
#
# Identifiers are PROVISIONAL — see PROVISIONAL_FRAMEWORKS above.
_NCA_CCC_SUBDOMAINS: Tuple[Tuple[str, str, str], ...] = (
    (_nca(1, 1), 'Cybersecurity strategy and governance', 'not-evidenced'),
    (_nca(1, 2), 'Cybersecurity risk management', 'not-evidenced'),
    (_nca(1, 3), 'Cybersecurity in change management and IT projects', 'not-evidenced'),
    (_nca(1, 4), 'Compliance with regulations and standards', 'not-evidenced'),
    (_nca(1, 5), 'Periodical cybersecurity review and audit', 'not-evidenced'),
    (_nca(1, 6), 'Human resources and cybersecurity awareness', 'not-evidenced'),
    (_nca(2, 1), 'Asset management', 'not-evidenced'),
    (_nca(2, 2), 'Identity and access management', 'evidenced'),
    (_nca(2, 3), 'Information system and processing facilities protection', 'partial'),
    (_nca(2, 4), 'Network security management', 'evidenced'),
    (_nca(2, 5), 'Mobile devices security', 'not-evidenced'),
    (_nca(2, 6), 'Data and information protection', 'evidenced'),
    (_nca(2, 7), 'Cryptography', 'evidenced'),
    (_nca(2, 8), 'Backup and recovery management', 'partial'),
    (_nca(2, 9), 'Vulnerabilities management', 'partial'),
    (_nca(2, 10), 'Penetration testing', 'not-evidenced'),
    (_nca(2, 11), 'Cybersecurity event logs and monitoring management', 'evidenced'),
    (_nca(2, 12), 'Cybersecurity incident and threat management', 'not-evidenced'),
    (_nca(2, 13), 'Physical security', 'not-evidenced'),
    (_nca(2, 14), 'Web application security', 'not-evidenced'),
    (_nca(3, 1), 'Cybersecurity resilience aspects of business continuity', 'partial'),
    (_nca(4, 1), 'Third-party cybersecurity', 'not-evidenced'),
    (_nca(4, 2), 'Cloud computing and hosting cybersecurity', 'not-evidenced'),
)

# UAE Information Assurance Standard (SIA, formerly NESA), family level.
# The IAS follows the ISO/IEC 27001:2005 control structure, which is why
# cryptography sits under T7 (systems acquisition, development and maintenance)
# and logging under T3 (operations management) rather than where a reader of
# the 2022 revision would expect them.
_NESA_IAS_FAMILIES: Tuple[Tuple[str, str, str], ...] = (
    (_nesa('M1'), 'Strategy and planning', 'not-evidenced'),
    (_nesa('M2'), 'Information security risk management', 'not-evidenced'),
    (_nesa('M3'), 'Awareness and training', 'not-evidenced'),
    (_nesa('M4'), 'Human resources security', 'not-evidenced'),
    (_nesa('M5'), 'Compliance', 'not-evidenced'),
    (_nesa('M6'), 'Performance evaluation and improvement', 'not-evidenced'),
    (_nesa('T1'), 'Asset management', 'not-evidenced'),
    (_nesa('T2'), 'Physical and environmental security', 'not-evidenced'),
    (_nesa('T3'), 'Operations management', 'evidenced'),
    (_nesa('T4'), 'Communications', 'evidenced'),
    (_nesa('T5'), 'Access control', 'evidenced'),
    (_nesa('T6'), 'Third-party security', 'not-evidenced'),
    (_nesa('T7'), 'Information systems acquisition, development and maintenance', 'evidenced'),
    (_nesa('T8'), 'Information security incident management', 'not-evidenced'),
    (_nesa('T9'), 'Information systems continuity management', 'partial'),
)

_ARTICLES_BY_FRAMEWORK = {
    'DORA': _DORA_ARTICLES,
    'NIS2': _NIS2_MEASURES,
    'NCA-CCC': _NCA_CCC_SUBDOMAINS,
    'NESA-IAS': _NESA_IAS_FAMILIES,
}


# ── mapping rules ────────────────────────────────────────────────────────────
# Base layer: the control domain ComplianceService already infers for every
# finding, whichever scanner produced it. 'configuration' is also that
# inference's catch-all for unmatched findings, so it maps only to the weakest
# defensible pair — a misconfiguration is evidence about ICT system upkeep
# (DORA Art. 7) and system maintenance (NIS2 (e)), and nothing stronger.
_BY_DOMAIN: Dict[str, Dict[str, List[str]]] = {
    'identity': {'DORA': [_dora(9)], 'NIS2': [_nis2('i')],
                 'NCA-CCC': [_nca(2, 2)], 'NESA-IAS': [_nesa('T5')]},
    # Same articles as identity — a credential in source is an access-management
    # failure — plus the secure-development article, which is what makes it
    # different from a runtime access finding.
    'secrets': {'DORA': [_dora(9)], 'NIS2': [_nis2('i')],
                'NCA-CCC': [_nca(2, 2)], 'NESA-IAS': [_nesa('T5')]},
    'storage': {'DORA': [_dora(9)], 'NIS2': [_nis2('i')],
                'NCA-CCC': [_nca(2, 6)], 'NESA-IAS': [_nesa('T5')]},
    'database': {'DORA': [_dora(9)], 'NIS2': [_nis2('i')],
                 'NCA-CCC': [_nca(2, 6)], 'NESA-IAS': [_nesa('T5')]},
    'network': {'DORA': [_dora(9)], 'NIS2': [_nis2('e')],
                'NCA-CCC': [_nca(2, 4)], 'NESA-IAS': [_nesa('T4')]},
    'logging': {'DORA': [_dora(10)], 'NIS2': [_nis2('b')],
                'NCA-CCC': [_nca(2, 11)], 'NESA-IAS': [_nesa('T3')]},
    'monitoring': {'DORA': [_dora(10)], 'NIS2': [_nis2('b')],
                   'NCA-CCC': [_nca(2, 11)], 'NESA-IAS': [_nesa('T3')]},
    'configuration': {'DORA': [_dora(7)], 'NIS2': [_nis2('e')],
                      'NCA-CCC': [_nca(2, 3)], 'NESA-IAS': [_nesa('T3')]},
}

# Refinement layer: articles whose subject cuts across domains. Backup and
# resilience findings land in the 'configuration' domain because
# _infer_control_domain has no resilience bucket, and widening that inference
# would strip the existing SOC2/ISO crosswalk off those same findings — so the
# refinement reads the finding text here instead.
_BY_KEYWORD: Tuple[Tuple[Sequence[str], Dict[str, List[str]]], ...] = (
    (('encrypt', 'kms', 'key vault', 'cmk', 'tls', 'ssl', 'at rest', 'in transit'),
     {'DORA': [_dora(9)], 'NIS2': [_nis2('h')],
      'NCA-CCC': [_nca(2, 7)], 'NESA-IAS': [_nesa('T7')]}),
    (('mfa', 'multi-factor', 'multifactor'),
     {'DORA': [_dora(9)], 'NIS2': [_nis2('j')],
      'NCA-CCC': [_nca(2, 2)], 'NESA-IAS': [_nesa('T5')]}),
    # 'soft delete' / 'purge protection' are recoverability controls (Azure Key
    # Vault, Storage). Without them here they matched only the encryption rule
    # below and lost their backup/restoration article.
    (('backup', 'versioning', 'snapshot', 'replication', 'retention', 'point-in-time',
      'pitr', 'soft delete', 'purge protection', 'recovery point'),
     {'DORA': [_dora(12)], 'NIS2': [_nis2('c')],
      'NCA-CCC': [_nca(2, 8)], 'NESA-IAS': [_nesa('T3')]}),
    (('multi-az', 'multi az', 'availability zone', 'deletion protection', 'failover',
      'redundan', 'disaster recovery'),
     {'DORA': [_dora(11)], 'NIS2': [_nis2('c')],
      'NCA-CCC': [_nca(3, 1)], 'NESA-IAS': [_nesa('T9')]}),
    (('patch', 'vulnerab', 'cve', 'minor version', 'auto minor', 'auto upgrade',
      'end of life', 'deprecated'),
     {'DORA': [_dora(7)], 'NIS2': [_nis2('e')],
      'NCA-CCC': [_nca(2, 9)], 'NESA-IAS': [_nesa('T7')]}),
)


def overlays_for(domain: str, text: str = '') -> Dict[str, Set[str]]:
    """Regulatory controls for one finding, as ``{framework: {controls}}``.

    ``domain`` is the control domain ComplianceService inferred; ``text`` is the
    finding's searchable blob, used only to refine cross-cutting articles.
    Returns ``{}`` when neither yields a defensible mapping.
    """
    result: Dict[str, Set[str]] = {}

    def _merge(mapping: Dict[str, List[str]]) -> None:
        for framework, controls in mapping.items():
            result.setdefault(framework, set()).update(controls)

    base = _BY_DOMAIN.get((domain or '').strip().lower())
    if base:
        _merge(base)

    haystack = (text or '').lower()
    if haystack:
        for terms, mapping in _BY_KEYWORD:
            if any(term in haystack for term in terms):
                _merge(mapping)

    return result


def article_coverage(framework: str) -> List[Dict[str, str]]:
    """Every article of ``framework`` with its evidence status — including the
    ones we cannot evidence, which is the point. Returns [] for anything that
    is not a regulatory overlay."""
    articles = _ARTICLES_BY_FRAMEWORK.get((framework or '').strip().upper(), ())
    return [
        {'article': article, 'title': title, 'status': status}
        for article, title, status in articles
    ]
