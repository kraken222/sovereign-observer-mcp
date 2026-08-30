# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/hcl_locator.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""Resolve Terraform findings back to a precise file:line in the HCL source.

Terraform *plan JSON* (what the scanner evaluates) does not carry source
locations — every resource shows ``line: 0``. To surface a finding as an inline
PR annotation ("aws_s3_bucket.data is public — main.tf:42"), we must look the
resource up in the raw ``.tf`` source the CI job has on disk.

``HclLocator`` builds a lightweight index of ``resource "<type>" "<name>"`` and
``data "<type>" "<name>"`` declarations across every supplied source file, then
answers ``locate(address, attribute)`` for a Terraform resource address such as
``aws_s3_bucket.data`` or ``module.app.aws_s3_bucket.data["primary"]``.

This is intentionally a pragmatic line scanner, not a full HCL2 parser: it has
zero third-party dependencies, never executes the config, and degrades to a
best-effort block match when an attribute can't be pinpointed. That trade keeps
it safe to run inside the customer's CI and trivial to unit-test.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# `resource "aws_s3_bucket" "data" {`  /  `data "aws_ami" "ubuntu" {`
_DECL_RE = re.compile(
    r'^\s*(?P<kind>resource|data)\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{?'
)
# A top-level attribute assignment or nested block opener inside a resource body.
_INDEX_SUFFIX_RE = re.compile(r'\[[^\]]*\]')


class HclLocator:
    """Index .tf sources and resolve resource addresses to {file, line}."""

    def __init__(self, sources: Dict[str, str]):
        """sources: mapping of file path -> full file contents."""
        self._sources = sources or {}
        # (type, name) -> list of (file, decl_line_1based, decl_index_in_lines)
        self._index: Dict[Tuple[str, str], List[Tuple[str, int, int]]] = {}
        self._lines_cache: Dict[str, List[str]] = {}
        self._build_index()

    # ── indexing ────────────────────────────────────────────────────────
    def _build_index(self) -> None:
        for path, content in self._sources.items():
            if not isinstance(content, str):
                continue
            lines = content.splitlines()
            self._lines_cache[path] = lines
            for i, line in enumerate(lines):
                m = _DECL_RE.match(line)
                if not m:
                    continue
                key = (m.group("type"), m.group("name"))
                self._index.setdefault(key, []).append((path, i + 1, i))

    # ── address parsing ─────────────────────────────────────────────────
    @staticmethod
    def parse_address(address: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract (type, name) from a Terraform resource address.

        Handles module prefixes and index suffixes:
          aws_s3_bucket.data                        -> (aws_s3_bucket, data)
          module.app.aws_s3_bucket.data             -> (aws_s3_bucket, data)
          module.app.aws_s3_bucket.data["primary"]  -> (aws_s3_bucket, data)
          data.aws_ami.ubuntu                       -> (aws_ami, ubuntu)
        The resource type and name are always the final two dotted segments
        once index brackets are stripped.
        """
        if not address or not isinstance(address, str):
            return None, None
        clean = _INDEX_SUFFIX_RE.sub("", address).strip()
        parts = [p for p in clean.split(".") if p]
        if len(parts) < 2:
            return None, None
        return parts[-2], parts[-1]

    # ── lookup ──────────────────────────────────────────────────────────
    def locate(
        self,
        address: str,
        attribute: Optional[str] = None,
        prefer_files: Optional[List[str]] = None,
    ) -> Optional[Dict[str, object]]:
        """Return {"file", "line", "match": "resource"|"attribute"} or None.

        If ``attribute`` is given (e.g. "acl" or "versioning.enabled") we try to
        pinpoint the attribute's line within the resource block; on failure we
        fall back to the resource declaration line. When the same type.name
        exists in more than one file, ``prefer_files`` (typically the PR's
        changed files) breaks the tie.
        """
        rtype, rname = self.parse_address(address)
        if not rtype or not rname:
            return None
        candidates = self._index.get((rtype, rname))
        if not candidates:
            return None

        path, decl_line, decl_idx = self._choose(candidates, prefer_files)

        result: Dict[str, object] = {"file": path, "line": decl_line, "match": "resource"}
        if attribute:
            attr_line = self._locate_attribute(path, decl_idx, attribute)
            if attr_line is not None:
                result["line"] = attr_line
                result["match"] = "attribute"
        return result

    def _choose(
        self,
        candidates: List[Tuple[str, int, int]],
        prefer_files: Optional[List[str]],
    ) -> Tuple[str, int, int]:
        if prefer_files:
            preferred = set(prefer_files)
            for cand in candidates:
                if cand[0] in preferred:
                    return cand
        return candidates[0]

    def _locate_attribute(self, path: str, decl_idx: int, attribute: str) -> Optional[int]:
        """Find an attribute's line within the resource block starting at decl_idx.

        Supports dotted attributes ("versioning.enabled") by descending into
        nested blocks. Brace counting keeps the search inside this resource's
        body so we never bleed into a sibling resource.
        """
        lines = self._lines_cache.get(path)
        if not lines:
            return None

        tokens = [t for t in attribute.split(".") if t]
        if not tokens:
            return None

        # Establish the block's line span via brace counting from the decl line.
        start, end = self._block_span(lines, decl_idx)
        search_start = start
        search_end = end
        found_line: Optional[int] = None

        for depth, token in enumerate(tokens):
            token_line, token_idx = self._find_token(lines, search_start, search_end, token)
            if token_line is None:
                # Could not resolve this segment — return best match so far.
                return found_line
            found_line = token_line
            # For the next dotted segment, narrow the search to this token's
            # nested block (if it opens one).
            if depth < len(tokens) - 1:
                search_start, search_end = self._block_span(lines, token_idx)
        return found_line

    @staticmethod
    def _block_span(lines: List[str], open_idx: int) -> Tuple[int, int]:
        """Return (start_idx, end_idx_inclusive) for the block whose opening
        brace is on or after ``open_idx``. Falls back to a window if no braces."""
        depth = 0
        seen_open = False
        n = len(lines)
        i = open_idx
        while i < n:
            depth += lines[i].count("{") - lines[i].count("}")
            if "{" in lines[i]:
                seen_open = True
            if seen_open and depth <= 0:
                return open_idx, i
            i += 1
        return open_idx, n - 1

    @staticmethod
    def _find_token(
        lines: List[str], start_idx: int, end_idx: int, token: str
    ) -> Tuple[Optional[int], Optional[int]]:
        """Find `token =` or `token {` between start_idx and end_idx (inclusive).
        Returns (line_1based, line_idx) or (None, None)."""
        pat = re.compile(rf'^\s*{re.escape(token)}\s*(=|\{{|")')
        # Skip the declaration line itself (start_idx).
        for i in range(start_idx + 1, min(end_idx, len(lines) - 1) + 1):
            if pat.match(lines[i]):
                return i + 1, i
        return None, None
