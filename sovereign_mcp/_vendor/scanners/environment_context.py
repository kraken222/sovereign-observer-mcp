# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/environment_context.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""Which environment is this Terraform for, and does that change the severity?

The problem this solves
-----------------------
A scanner that reports the same severity everywhere gets muted. Multi-AZ and
deletion protection are the right call in production and pure noise in a dev
sandbox that is torn down nightly — and once a developer has dismissed the same
Critical five times on a scratch stack, they stop reading the output entirely.
The finding was correct; reporting it at that severity was not.

So severity is allowed to depend on the environment. Two things keep that from
becoming a hole you can drive a truck through.

**Only some checks may move.** ``ENVIRONMENT_SENSITIVE_CHECKS`` is an explicit,
hand-picked allowlist of resilience, monitoring and housekeeping checks. Public
exposure, encryption, and credentials in source are *not* on it and never will
be: a public bucket in dev is a public bucket, and the data in a dev database is
usually last month's production dump. Anything not on the list keeps its
severity in every environment, which means the failure mode of this module is
"too noisy", never "quietly stopped reporting the thing that mattered".

**Lowering is opt-in.** Inference runs always, because knowing the environment
is free and useful. Applying it is a decision the caller makes, because a scan
that silently downgrades a finding below someone's existing merge gate has
weakened their pipeline without asking. See ``adjust_severity``.

Inference is best-effort and says so. ``UNKNOWN`` is a normal answer and means
"change nothing", not "assume development".

Only two things are treated as evidence: an environment tag on the resource, and
the directory the file sits in. Both are deliberate statements about where
something belongs. A resource's own name is not — reading ``development`` out of
``aws_db_instance.scratch`` would let a naming habit silently lower findings on a
production stack.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

PRODUCTION = "production"
STAGING = "staging"
DEVELOPMENT = "development"
UNKNOWN = "unknown"

# Written most-specific first: 'preprod' has to beat 'prod', or every staging
# stack is classified as production and the whole module does nothing.
_ALIASES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (STAGING, ("preprod", "pre-prod", "pre_prod", "staging", "stage", "stg",
               "uat", "qa", "sit", "test", "testing")),
    (PRODUCTION, ("production", "prod", "prd", "live")),
    (DEVELOPMENT, ("development", "develop", "dev", "sandbox", "sbx", "scratch",
                   "local", "playground", "demo")),
)

# Tag keys that name an environment. Exact keys, lowercased — 'environment_type'
# and 'env_owner' are something else and must not match.
_ENV_TAG_KEYS = frozenset({"environment", "env", "stage", "tier"})

_TAG_ASSIGNMENT = re.compile(
    r'^\s*"?(?P<key>[A-Za-z_][A-Za-z0-9_-]*)"?\s*[=:]\s*"(?P<value>[^"]*)"'
)
_BLOCK_HEADER = re.compile(
    r'^\s*(?P<kind>resource|data|module)\s+(?P<labels>[^{]*)\{'
)
_QUOTED_LABEL = re.compile(r'"([^"]*)"')
_HCL_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')

# Path segments are a strong signal: envs/prod/main.tf, live/production/rds.tf.
# Split on the usual separators so 'prod-network' and 'prod_network' both hit.
_PATH_SPLIT = re.compile(r"[/\\._\-]+")


def normalise(value: Optional[str]) -> str:
    """Map a raw string ('PRD', 'pre-prod', 'sandbox') onto one of the four."""
    if not value:
        return UNKNOWN
    token = str(value).strip().lower()
    if not token:
        return UNKNOWN
    for env, aliases in _ALIASES:
        if token in aliases:
            return env
    # Fall back to a token-wise match so 'acme-prod-db' and 'us-east-1-dev'
    # resolve. Same most-specific-first ordering.
    parts = [p for p in _PATH_SPLIT.split(token) if p]
    for env, aliases in _ALIASES:
        if any(p in aliases for p in parts):
            return env
    return UNKNOWN


def from_path(path: str) -> str:
    """Infer from a file path: ``environments/prod/rds.tf`` -> production."""
    return normalise(path)


def from_sources(sources: Dict[str, str]) -> Dict[str, str]:
    """``resource_address -> environment`` for everything the sources declare.

    A resource's own environment tag beats the path it happens to live in, which
    is the right precedence: someone who tagged a resource ``Environment =
    "production"`` inside ``modules/database`` meant it.
    """
    resolved: Dict[str, str] = {}
    for path, content in (sources or {}).items():
        if not isinstance(content, str):
            continue
        file_env = from_path(path)
        for address, tag_env in _iter_block_environments(content):
            env = tag_env if tag_env != UNKNOWN else file_env
            # Note what is deliberately NOT a signal: the resource's own name.
            # `aws_s3_bucket.demo` or `aws_db_instance.scratch` in a production
            # account would otherwise have its findings lowered on the strength
            # of what someone called a variable. A tag and a directory are
            # declarations about an environment; a local name is not.
            # First declaration wins; a later file re-declaring the same address
            # is a configuration error, not a signal.
            resolved.setdefault(address, env)
    return resolved


def _iter_block_environments(content: str):
    """Yield ``(resource_address, environment)`` per top-level block."""
    address = ""
    depth = 0
    found = UNKNOWN
    for raw_line in content.splitlines():
        stripped = _HCL_STRING.sub('""', raw_line)

        if depth == 0:
            header = _BLOCK_HEADER.match(raw_line)
            if header:
                labels = _QUOTED_LABEL.findall(header.group("labels") or "")
                kind = header.group("kind")
                if labels:
                    address = (
                        ".".join(labels) if kind == "resource"
                        else ".".join([kind, *labels])
                    )
                found = UNKNOWN

        if address:
            match = _TAG_ASSIGNMENT.match(raw_line)
            if match and match.group("key").lower() in _ENV_TAG_KEYS:
                candidate = normalise(match.group("value"))
                if candidate != UNKNOWN:
                    found = candidate

        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            depth = 0
            if address:
                yield address, found
            address = ""
            found = UNKNOWN


# ── which checks may move, and how far ───────────────────────────────────────
# Resilience, monitoring and housekeeping. Every one of these is a real finding
# that a throwaway stack does not need to act on today.
#
# Deliberately absent, and the reason it is worth being strict about: public
# access (CKV_AWS_17/24/25/53-56, CKV2_AWS_6), encryption (CKV_AWS_16/145/19),
# IAM (CKV_AWS_40/161) and credentials in source (SOV_SECRET_1). A dev
# environment is where the last production dump usually lives, and its blast
# radius into the rest of the account is the same as anything else's.
ENVIRONMENT_SENSITIVE_CHECKS = frozenset({
    "CKV_AWS_157",   # RDS Multi-AZ
    "CKV_AWS_293",   # RDS deletion protection
    "CKV_AWS_118",   # RDS enhanced monitoring
    "CKV_AWS_353",   # RDS performance insights
    "CKV_AWS_129",   # RDS log exports to CloudWatch
    "CKV_AWS_226",   # RDS auto minor version upgrade
    "CKV2_AWS_30",   # RDS (postgres) query logging
    "CKV2_AWS_60",   # RDS copy tags to snapshots
    "CKV_AWS_144",   # S3 cross-region replication
    "CKV2_AWS_61",   # S3 lifecycle configuration
    "CKV2_AWS_62",   # S3 event notifications
    "CKV_AWS_23",    # security-group rule descriptions
    "CKV2_AWS_5",    # security group attached to a resource
})

_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

# How many steps down an environment-sensitive finding drops. Production never
# moves, and neither does UNKNOWN — an inference that failed must not be able to
# lower anything.
_ATTENUATION = {
    PRODUCTION: 0,
    UNKNOWN: 0,
    STAGING: 1,
    DEVELOPMENT: 2,
}

# Nothing is attenuated below this. A finding that disappears is worse than a
# finding that is quiet: Low still shows up in the report and in the history.
_FLOOR = "Low"


def adjust_severity(check_id: str, severity: str, environment: str) -> Tuple[str, Optional[str]]:
    """Return ``(severity, reason)``; ``reason`` is None when nothing changed."""
    steps = _ATTENUATION.get(environment, 0)
    if not steps or check_id not in ENVIRONMENT_SENSITIVE_CHECKS:
        return severity, None
    if severity not in _ORDER:
        return severity, None

    floor_index = _ORDER.index(_FLOOR)
    current = _ORDER.index(severity)
    lowered = max(floor_index, current - steps)
    if lowered == current:
        return severity, None

    return _ORDER[lowered], (
        f"{severity} in production; lowered for a {environment} environment "
        f"because this check is about resilience and operability rather than "
        f"exposure. Severity is never lowered for public access, encryption, "
        f"identity or credentials in source."
    )


def annotate(findings: List[dict], sources: Dict[str, str], apply_severity: bool) -> List[dict]:
    """Tag findings with their environment, and optionally re-rank them.

    ``apply_severity=False`` (the default everywhere) annotates only. Turning it
    on is the caller saying it accepts that some findings will be reported below
    the level their merge gate keys on.
    """
    by_address = from_sources(sources)
    for item in findings:
        env = by_address.get(item.get("resource_address") or "")
        if env is None:
            env = from_path(item.get("file") or "")
        item["environment"] = env

        if not apply_severity:
            continue

        new_severity, reason = adjust_severity(
            item.get("check_id") or "", item.get("severity") or "", env
        )
        if reason:
            item["severity_before_environment"] = item["severity"]
            item["severity"] = new_severity
            item["severity_adjusted_because"] = reason
    return findings
