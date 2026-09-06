#!/usr/bin/env python3
"""Sync this package into the public ``sovereign-observer-mcp`` checkout.

Why this exists
---------------
The public repository is not a fork and not a subtree — it is a curated copy.
Most of it is byte-identical to ``integrations/mcp-server``, three files exist
only there (licence, notice, gitignore), and the README deliberately says
something different because the two repositories have different relationships
to ``_vendor``: it is generated and gitignored here, committed there so the
package builds on its own.

That is a small enough set of rules to hold in your head, and exactly the kind
of thing that gets it wrong at 1am before a release. The 0.2.0 sync was done by
hand and a README paragraph nearly went missing.

The two failure modes worth engineering against
-----------------------------------------------
*Silently dropping a file.* A new source module that never reaches the mirror
produces a package that imports fine here and crashes there. So anything not
explicitly classified is copied, and anything that vanished upstream is deleted
from the mirror rather than left to rot.

*Silently clobbering divergence.* Copying the README over would delete the
mirror's own Development section, and nobody would notice until a contributor
followed instructions that do not apply. So divergent files are never copied.
Instead the script records the upstream hash at each sync and stops when
upstream moves, showing what changed so it can be ported deliberately.

Usage
-----
    python scripts/sync_mirror.py --mirror ../../../sovereign-observer-mcp
    python scripts/sync_mirror.py --mirror <path> --apply

Dry run by default: it prints the plan and writes nothing.
"""
from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
PKG_ROOT = HERE.parent

# Present only in the mirror. Never written, never deleted, never reported.
MIRROR_ONLY = {
    ".gitignore",   # the mirror commits _vendor; this repo ignores it
    "LICENSE",
    "NOTICE",
}

# Exists in both and is *meant* to differ. Never copied. The script tracks the
# upstream version's hash so it can tell you when your change needs porting by
# hand — see _check_divergent.
DIVERGENT = {
    "README.md",
}

# Directories that are build or test residue in either tree.
PRUNE_DIRS = {"__pycache__", ".pytest_cache", ".git", "dist", "build", ".ruff_cache"}

# Where the upstream hashes of DIVERGENT files are recorded, in the mirror.
LEDGER_NAME = ".mirror-sync.json"


def _tracked_files(root: Path, include_vendor: bool) -> List[str]:
    """Relative posix paths under ``root``, minus residue.

    ``_vendor`` is generated here and committed there, so it is synced like any
    other content — but only once it has actually been generated.
    """
    out: List[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(root).parts)
        if parts & PRUNE_DIRS:
            continue
        rel = path.relative_to(root).as_posix()
        if rel.endswith(".egg-info") or ".egg-info/" in rel:
            continue
        if not include_vendor and rel.startswith("sovereign_mcp/_vendor/"):
            continue
        out.append(rel)
    return sorted(out)


def _digest(path: Path) -> str:
    """Content hash, insensitive to line endings.

    The mirror is cloned on Windows with autocrlf, so a byte-for-byte compare
    would report every file as changed on every run and the report would become
    noise nobody reads.
    """
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _same(a: Path, b: Path) -> bool:
    if not b.exists():
        return False
    if filecmp.cmp(a, b, shallow=False):
        return True
    return _digest(a) == _digest(b)


def _load_ledger(mirror: Path) -> Dict[str, str]:
    path = mirror / LEDGER_NAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("divergent_upstream", {})
    except (ValueError, OSError):
        return {}


def _check_divergent(mirror: Path, ledger: Dict[str, str]) -> Tuple[List[str], Dict[str, str]]:
    """Which divergent files moved upstream since the last sync."""
    drifted: List[str] = []
    current: Dict[str, str] = {}
    for rel in sorted(DIVERGENT):
        upstream = PKG_ROOT / rel
        if not upstream.is_file():
            continue
        current[rel] = _digest(upstream)
        if ledger.get(rel) != current[rel]:
            drifted.append(rel)
    return drifted, current


def _vendor() -> None:
    """Generate ``_vendor`` so there is something to copy."""
    subprocess.run(
        [sys.executable, str(HERE / "vendor_engine.py")],
        check=True,
        cwd=str(PKG_ROOT),
    )


def plan(mirror: Path) -> Tuple[List[str], List[str], List[str]]:
    """``(added, updated, removed)`` — what a sync would do."""
    upstream = _tracked_files(PKG_ROOT, include_vendor=True)
    existing = _tracked_files(mirror, include_vendor=True)

    syncable = [r for r in upstream if r not in DIVERGENT and r not in MIRROR_ONLY]

    added, updated = [], []
    for rel in syncable:
        dest = mirror / rel
        if not dest.exists():
            added.append(rel)
        elif not _same(PKG_ROOT / rel, dest):
            updated.append(rel)

    keep = set(syncable) | DIVERGENT | MIRROR_ONLY | {LEDGER_NAME}
    removed = [r for r in existing if r not in keep]

    return added, updated, removed


def apply(mirror: Path, added: List[str], updated: List[str], removed: List[str],
          hashes: Dict[str, str]) -> None:
    for rel in added + updated:
        dest = mirror / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PKG_ROOT / rel, dest)

    for rel in removed:
        (mirror / rel).unlink()

    # Prune directories the removals emptied, so a deleted module does not leave
    # an empty package behind that still imports.
    for path in sorted(mirror.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and not any(path.iterdir()) and ".git" not in path.parts:
            path.rmdir()

    (mirror / LEDGER_NAME).write_text(
        json.dumps(
            {
                "_comment": (
                    "Upstream hashes of files that deliberately differ in this "
                    "mirror. scripts/sync_mirror.py stops when one of these moves "
                    "upstream, so the change is ported by hand rather than "
                    "clobbering the mirror's own text. Written by the script."
                ),
                "divergent_upstream": hashes,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _report(title: str, items: List[str]) -> None:
    if not items:
        return
    print(f"\n{title} ({len(items)})")
    for rel in items:
        print(f"  {rel}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mirror", required=True, type=Path,
                    help="path to a sovereign-observer-mcp checkout")
    ap.add_argument("--apply", action="store_true",
                    help="write the changes (default is a dry run)")
    ap.add_argument("--accept-divergent", action="store_true",
                    help="record the current upstream hashes for divergent files "
                         "without porting them — use only after porting by hand")
    ap.add_argument("--skip-vendor", action="store_true",
                    help="do not regenerate _vendor first")
    args = ap.parse_args()

    mirror = args.mirror.expanduser().resolve()
    if not (mirror / "pyproject.toml").is_file():
        print(f"error: {mirror} does not look like a checkout of the mirror", file=sys.stderr)
        return 2

    if not args.skip_vendor:
        _vendor()
    if not (PKG_ROOT / "sovereign_mcp" / "_vendor" / "scanners" / "checkov_scanner.py").is_file():
        print("error: _vendor is missing — the mirror commits it, so it must exist "
              "before syncing. Drop --skip-vendor.", file=sys.stderr)
        return 2

    ledger = _load_ledger(mirror)
    drifted, hashes = _check_divergent(mirror, ledger)

    added, updated, removed = plan(mirror)

    print(f"upstream : {PKG_ROOT}")
    print(f"mirror   : {mirror}")
    _report("add", added)
    _report("update", updated)
    _report("remove", removed)

    if not (added or updated or removed):
        print("\nnothing to sync")

    if drifted and not args.accept_divergent:
        print(
            "\n" + "-" * 68 +
            "\nSTOP: these files differ deliberately between the two repositories,"
            "\nand the upstream version changed since the last sync. Port the change"
            "\ninto the mirror by hand, keeping its own wording, then re-run with"
            "\n--accept-divergent to record the new hash.\n"
        )
        for rel in drifted:
            print(f"  {rel}")
            print(f"    diff: git diff --no-index -- {mirror / rel} {PKG_ROOT / rel}")
        print("-" * 68)
        return 1

    if not args.apply:
        print("\ndry run — nothing written. Re-run with --apply.")
        return 0

    apply(mirror, added, updated, removed, hashes)
    print("\napplied.")
    print("Next: run the mirror's own suite, then commit and push from there.")
    print(f"  cd {mirror} && python -m pytest -q")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
