# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from backend/app/services/scanners/hcl_to_plan.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
"""Best-effort HCL → Terraform plan JSON converter.

Sovereign's IaC scanner consumes Terraform *plan JSON* (the output of
``terraform show -json plan.tfplan``). When a user pastes raw ``.tf`` source
or we pull ``.tf`` files from a GitHub repo, we don't have a plan — we have
HCL. This module synthesizes a minimal plan-JSON shape so the existing
``map_terraform_to_inventory`` keeps working unchanged.

Scope: a pragmatic regex/state-machine parser, not a full HCL2 implementation.
It covers what the rule packs actually evaluate on:

* ``resource "<type>" "<name>" { ... }`` blocks
* scalar attributes (string / number / bool)
* nested blocks, normalized to ``key: [ {...} ]`` (matching plan JSON's list-
  of-block convention for ``backup_configuration``, ``network_interface``, …)
* list-of-strings attributes (``cidr_blocks = ["0.0.0.0/0"]``)
* unresolved references (``var.foo``, ``module.x.y``) preserved as raw text
  so engines that string-match still see them

Anything weirder (heredocs, ternaries, ``for`` expressions, splats) is kept
as the original raw text — better to see a string than crash mid-parse.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# resource "aws_s3_bucket" "data" {
_RESOURCE_HEADER_RE = re.compile(
    r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{\s*$'
)
# attribute = value   OR   block_name {
_ATTR_RE = re.compile(r'^\s*(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)\s*=\s*(?P<val>.*?)\s*$')
_BLOCK_OPEN_RE = re.compile(r'^\s*(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)\s*\{\s*$')


def _strip_comments(text: str) -> str:
    # Strip // and # single-line, and /* ... */ multi-line.
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    out_lines = []
    for line in text.splitlines():
        s = line
        # Honor `#` and `//` outside of quoted strings — simple state machine.
        in_str = False
        quote = None
        i = 0
        cut = None
        while i < len(s):
            c = s[i]
            if in_str:
                if c == '\\' and i + 1 < len(s):
                    i += 2
                    continue
                if c == quote:
                    in_str = False
                    quote = None
            else:
                if c in ('"', "'"):
                    in_str = True
                    quote = c
                elif c == '#':
                    cut = i
                    break
                elif c == '/' and i + 1 < len(s) and s[i + 1] == '/':
                    cut = i
                    break
            i += 1
        out_lines.append(s if cut is None else s[:cut])
    return '\n'.join(out_lines)


def _coerce_scalar(raw: str) -> Any:
    """Turn a raw RHS token into JSON-ish value: string/number/bool/list."""
    raw = raw.strip()
    if not raw:
        return ""
    # Quoted string
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    low = raw.lower()
    if low == 'true':
        return True
    if low == 'false':
        return False
    if low == 'null':
        return None
    # Numeric
    if re.match(r'^-?\d+$', raw):
        try:
            return int(raw)
        except ValueError:
            pass
    if re.match(r'^-?\d+\.\d+$', raw):
        try:
            return float(raw)
        except ValueError:
            pass
    # Inline list  ["a", "b"]
    if raw.startswith('[') and raw.endswith(']'):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        items: List[Any] = []
        buf = ''
        depth = 0
        in_str = False
        quote = None
        for c in inner:
            if in_str:
                buf += c
                if c == quote:
                    in_str = False
                    quote = None
                continue
            if c in ('"', "'"):
                in_str = True
                quote = c
                buf += c
                continue
            if c in '[{(':
                depth += 1
                buf += c
                continue
            if c in ']})':
                depth -= 1
                buf += c
                continue
            if c == ',' and depth == 0:
                items.append(_coerce_scalar(buf))
                buf = ''
                continue
            buf += c
        if buf.strip():
            items.append(_coerce_scalar(buf))
        return items
    # Inline object  { key = "v", ... }   (rare on RHS; treat as raw)
    # Unresolved reference (var.x, local.y, module.z, aws_x.y.id) — keep as text.
    return raw


def _parse_block(lines: List[str], start: int) -> Tuple[Dict[str, Any], int]:
    """Parse the body of a `{ ... }` block starting at lines[start].

    Returns (block_dict, index_after_closing_brace).
    Nested blocks are accumulated as lists (HCL/Terraform plan JSON convention).
    """
    body: Dict[str, Any] = {}
    i = start
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == '' or stripped.startswith('#') or stripped.startswith('//'):
            i += 1
            continue
        if stripped == '}':
            return body, i + 1

        # Nested block: `network_interface {`
        m = _BLOCK_OPEN_RE.match(line)
        if m:
            key = m.group('key')
            nested, i = _parse_block(lines, i + 1)
            body.setdefault(key, []).append(nested)
            continue

        # Attribute on a single line: `key = value`
        m = _ATTR_RE.match(line)
        if m:
            key = m.group('key')
            val_text = m.group('val')

            # If the value is an opening bracket but unbalanced (multi-line list/object),
            # accumulate until balanced.
            opener = ''
            for c in val_text:
                if c in '[{':
                    opener = c
                    break
            if opener:
                closer = ']' if opener == '[' else '}'
                depth = val_text.count(opener) - val_text.count(closer)
                buf = val_text
                while depth > 0 and i + 1 < len(lines):
                    i += 1
                    buf += '\n' + lines[i]
                    depth += lines[i].count(opener) - lines[i].count(closer)
                # Object on RHS: convert minimal `key = value` pairs.
                if opener == '{':
                    inner = buf.strip()[1:-1]
                    body[key] = _parse_inline_object(inner)
                else:
                    body[key] = _coerce_scalar(buf)
                i += 1
                continue

            body[key] = _coerce_scalar(val_text)
            i += 1
            continue

        # Unknown / unparseable line — skip safely.
        i += 1
    # Unterminated block — return what we have.
    return body, i


def _parse_inline_object(inner: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    # split on commas at depth 0
    parts: List[str] = []
    buf = ''
    depth = 0
    in_str = False
    quote = None
    for c in inner:
        if in_str:
            buf += c
            if c == quote:
                in_str = False
                quote = None
            continue
        if c in ('"', "'"):
            in_str = True
            quote = c
            buf += c
            continue
        if c in '[{(':
            depth += 1
            buf += c
            continue
        if c in ']})':
            depth -= 1
            buf += c
            continue
        if c in ',\n' and depth == 0:
            if buf.strip():
                parts.append(buf)
            buf = ''
            continue
        buf += c
    if buf.strip():
        parts.append(buf)
    for p in parts:
        if '=' not in p:
            continue
        k, v = p.split('=', 1)
        out[k.strip()] = _coerce_scalar(v)
    return out


def parse_hcl_to_plan(sources: Dict[str, str]) -> Dict[str, Any]:
    """Convert ``{path: hcl_content}`` into a Terraform plan-JSON dict.

    Returns the same shape ``map_terraform_to_inventory`` expects:
    ``{"format_version": "1.0", "planned_values": {"root_module": {"resources": [...]}}}``.
    """
    resources: List[Dict[str, Any]] = []
    for path, content in (sources or {}).items():
        if not isinstance(content, str) or not content.strip():
            continue
        cleaned = _strip_comments(content)
        lines = cleaned.splitlines()
        i = 0
        while i < len(lines):
            m = _RESOURCE_HEADER_RE.match(lines[i])
            if not m:
                i += 1
                continue
            r_type = m.group('type')
            r_name = m.group('name')
            body, i = _parse_block(lines, i + 1)
            resources.append({
                'address': f'{r_type}.{r_name}',
                'mode': 'managed',
                'type': r_type,
                'name': r_name,
                'provider_name': r_type.split('_', 1)[0] if '_' in r_type else r_type,
                'schema_version': 0,
                'values': body,
                '__metadata': {'source_file': path},
            })
    return {
        'format_version': '1.0',
        'terraform_version': 'synth-from-hcl',
        'planned_values': {
            'root_module': {
                'resources': resources,
            }
        },
    }
