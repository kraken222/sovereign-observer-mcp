# ⚠ GENERATED FILE — DO NOT EDIT.
# Copied verbatim from integrations/github-action/scan.py by scripts/vendor_engine.py.
# Edit the backend module instead; this copy is regenerated at build time.
#!/usr/bin/env python3
"""Sovereign Observer — IaC PR scan entrypoint.

Runs inside CI (GitHub Actions / GitLab). It:
  1. Obtains a Terraform *plan JSON* (either supplied, or produced here).
  2. Collects the raw ``.tf`` sources + the PR's changed files.
  3. POSTs all three to the Sovereign ``/api/iac/scan-pr`` endpoint.
  4. Renders the response as inline annotations + a sticky PR comment, and
     exits non-zero when the merge gate is tripped.

Stdlib only — no pip install on the runner. Designed to be safe in a
customer's CI: it never applies Terraform and never prints the auth token.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

COMMENT_MARKER = "<!-- sovereign-iac-scan -->"


# ── small helpers ────────────────────────────────────────────────────────
def log(msg: str) -> None:
    print(f"[sovereign] {msg}", flush=True)


def fail(msg: str, code: int = 1) -> "None":
    print(f"::error::{msg}", flush=True)
    sys.exit(code)


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def run(cmd: list, cwd: str | None = None, check: bool = True) -> str:
    log("$ " + " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if check and proc.returncode != 0:
        fail(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc.stdout


# ── plan JSON acquisition ──────────────────────────────────────────────────
def load_plan_json(workdir: str) -> dict:
    """Return the Terraform plan as a dict, or ``{}`` if none is available.

    The backend's IaC engine (Checkov) evaluates the raw ``.tf`` sources
    directly, so a plan is **optional** — it is only needed for the legacy
    policy-engine fallback. We therefore make plan acquisition best-effort:
    if a plan can't be produced (no Terraform binary, no provider creds), we
    log and return ``{}`` rather than failing the whole scan.

    Preference order: an explicit plan-json file, then a binary plan file we
    convert with ``terraform show``, then a fresh ``terraform plan`` we run
    ourselves (init with -backend=false so no remote-state creds are needed).
    """
    plan_json_path = env("INPUT_PLAN_JSON")
    if plan_json_path:
        if not os.path.isfile(plan_json_path):
            fail(f"plan-json '{plan_json_path}' not found")
        with open(plan_json_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    plan_file = env("INPUT_PLAN_FILE")
    if plan_file:
        out = run(["terraform", f"-chdir={workdir}", "show", "-json", plan_file])
        return json.loads(out)

    if env("INPUT_RUN_TERRAFORM", "true").lower() != "true":
        log("run-terraform disabled and no plan supplied — scanning .tf sources only.")
        return {}

    # Best-effort: try to generate a plan ourselves. Any failure here is
    # non-fatal because Checkov scans the sources regardless.
    try:
        run(["terraform", f"-chdir={workdir}", "init", "-input=false", "-backend=false"], check=False)
        run(["terraform", f"-chdir={workdir}", "plan", "-input=false", "-out=sovereign.tfplan"],
            check=False)  # plan may exit 2 (changes) — that's fine
        out = run(["terraform", f"-chdir={workdir}", "show", "-json", "sovereign.tfplan"], check=False)
        return json.loads(out) if out.strip() else {}
    except Exception as e:  # noqa: BLE001 - plan is optional
        log(f"could not produce a Terraform plan ({e}); scanning .tf sources only.")
        return {}


# ── source + diff collection ───────────────────────────────────────────────
def collect_tf_sources(workdir: str, repo_root: str) -> dict:
    """Map repo-root-relative path -> file contents for every .tf under workdir.

    Paths are made relative to the repo root so annotation paths line up with
    the files GitHub shows in the PR diff."""
    sources: dict = {}
    for dirpath, dirnames, filenames in os.walk(workdir):
        # Skip provider/module caches — they're not the customer's code.
        dirnames[:] = [d for d in dirnames if d not in (".terraform", ".git")]
        for fn in filenames:
            if not fn.endswith(".tf"):
                continue
            full = os.path.join(dirpath, fn)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(full, repo_root).replace(os.sep, "/")
            sources[rel] = content
    return sources


def collect_changed_files(repo_root: str) -> list:
    """Best-effort list of .tf files changed in this PR (for tie-breaking when
    the same resource name exists in multiple files)."""
    base = env("INPUT_BASE_SHA") or env("GITHUB_BASE_REF")
    head = env("INPUT_HEAD_SHA") or env("GITHUB_SHA") or "HEAD"
    if not base:
        return []
    # Make sure the base ref is fetchable as a revision.
    ref = base if "/" not in base else f"origin/{base.split('/')[-1]}"
    try:
        out = subprocess.run(
            ["git", "-C", repo_root, "diff", "--name-only", f"{ref}...{head}"],
            capture_output=True, text=True,
        )
        names = out.stdout.splitlines() if out.returncode == 0 else []
    except OSError:
        names = []
    return [n.strip().replace(os.sep, "/") for n in names if n.strip().endswith(".tf")]


# ── API call ────────────────────────────────────────────────────────────────
def call_scan_api(api_url: str, token: str, body: dict) -> dict:
    url = api_url.rstrip("/") + "/api/iac/scan-pr"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-Sovereign-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        fail(f"scan API returned HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        fail(f"could not reach scan API at {url}: {e.reason}")
    return {}  # unreachable


# ── output rendering ────────────────────────────────────────────────────────
def emit_annotations(annotations: list) -> None:
    """Emit GitHub workflow-command annotations (inline on the PR diff)."""
    for a in annotations:
        level = a.get("annotation_level", "warning")
        cmd = "error" if level == "failure" else ("warning" if level == "warning" else "notice")
        path = a.get("path", "")
        line = a.get("start_line", 1)
        title = (a.get("title") or "").replace("\n", " ")
        # Workflow commands need newlines URL-encoded as %0A.
        message = (a.get("message") or "").replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        print(f"::{cmd} file={path},line={line},title={title}::{message}", flush=True)


def write_step_summary(markdown: str) -> None:
    path = env("GITHUB_STEP_SUMMARY")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(markdown + "\n")
        except OSError:
            pass


def upsert_pr_comment(markdown: str) -> None:
    """Create or update a single sticky comment on the PR."""
    gh_token = env("INPUT_GITHUB_TOKEN") or env("GITHUB_TOKEN")
    repo = env("GITHUB_REPOSITORY")
    pr_number = env("INPUT_PR_NUMBER")
    api = env("GITHUB_API_URL", "https://api.github.com")
    if not pr_number:
        pr_number = _pr_number_from_event()
    if not (gh_token and repo and pr_number):
        log("skipping PR comment (missing token/repo/pr number)")
        return

    body = markdown + "\n" + COMMENT_MARKER
    base = f"{api}/repos/{repo}"
    existing_id = None
    try:
        listing = _gh_request("GET", f"{base}/issues/{pr_number}/comments?per_page=100", gh_token)
        for c in listing or []:
            if COMMENT_MARKER in (c.get("body") or ""):
                existing_id = c.get("id")
                break
    except Exception as e:  # noqa: BLE001 - comment is best-effort
        log(f"could not list PR comments: {e}")

    payload = {"body": body}
    try:
        if existing_id:
            _gh_request("PATCH", f"{base}/issues/comments/{existing_id}", gh_token, payload)
            log("updated sticky PR comment")
        else:
            _gh_request("POST", f"{base}/issues/{pr_number}/comments", gh_token, payload)
            log("created PR comment")
    except Exception as e:  # noqa: BLE001
        log(f"could not post PR comment: {e}")


def _pr_number_from_event() -> str:
    event_path = env("GITHUB_EVENT_PATH")
    if event_path and os.path.isfile(event_path):
        try:
            with open(event_path, "r", encoding="utf-8") as fh:
                event = json.load(fh)
            pr = event.get("pull_request") or {}
            if pr.get("number"):
                return str(pr["number"])
            if event.get("number"):
                return str(event["number"])
        except (OSError, ValueError):
            pass
    return ""


def _gh_request(method: str, url: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


# ── opt-in auto-fix: open a reviewable PR with the safe fixes applied ─────────
def _addr_type_name(address):
    """``aws_db_instance.prod`` -> ('aws_db_instance', 'prod'); strips module
    prefixes and ``[idx]`` suffixes."""
    if not address:
        return None, None
    clean = re.sub(r"\[[^\]]*\]", "", address)
    parts = [p for p in clean.split(".") if p]
    if len(parts) < 2:
        return None, None
    return parts[-2], parts[-1]


def _is_literal_value(rhs: str) -> bool:
    """True if an attribute's right-hand side is a plain literal (bool, number,
    or quoted string) rather than an expression. Used to refuse overwriting a
    value wired to a variable/expression — Checkov may mis-evaluate it and the
    author chose it deliberately (the 'module passed vars' case)."""
    v = re.sub(r"#.*$", "", rhs).strip().rstrip(",").strip()
    if v in ("true", "false"):
        return True
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        return True
    if re.fullmatch(r'"[^"]*"', v):
        return True
    return False


def apply_attribute_fix(content, resource_address, attribute, value):
    """Set or add ``attribute = value`` inside the resource block for
    ``resource_address``. Returns ``(new_content, changed)``.

    Edits the first matching block only. If the attribute already has the
    desired value, nothing changes. If it is already wired to a variable or
    expression (e.g. ``= var.encrypt``), it is left untouched — we never clobber
    a deliberate, dynamic value over a Checkov verdict that may be wrong.
    Deliberately conservative — it only touches a single line, never reflows the
    block.
    """
    rtype, rname = _addr_type_name(resource_address)
    if not rtype or not rname:
        return content, False
    decl_re = re.compile(r'^(\s*)resource\s+"%s"\s+"%s"\s*\{'
                         % (re.escape(rtype), re.escape(rname)))
    attr_re = re.compile(r'^(\s*)%s\s*=' % re.escape(attribute))
    trailing_nl = content.endswith("\n")
    lines = content.splitlines()

    for i, line in enumerate(lines):
        m = decl_re.match(line)
        if not m:
            continue
        block_indent = m.group(1)
        # Find the block's closing brace via brace matching.
        depth = 0
        started = False
        end = len(lines) - 1
        for j in range(i, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                end = j
                break
        # Replace the attribute if present in the block body.
        for k in range(i + 1, end):
            am = attr_re.match(lines[k])
            if am:
                existing_rhs = lines[k].split("=", 1)[1] if "=" in lines[k] else ""
                # Don't overwrite a value the author wired to a variable/expression.
                if not _is_literal_value(existing_rhs):
                    return content, False
                new_line = f"{am.group(1)}{attribute} = {value}"
                if new_line == lines[k]:
                    return content, False
                lines[k] = new_line
                out = "\n".join(lines)
                return (out + "\n") if trailing_nl else out, True
        # Otherwise insert it right after the declaration line.
        lines.insert(i + 1, f"{block_indent}  {attribute} = {value}")
        out = "\n".join(lines)
        return (out + "\n") if trailing_nl else out, True
    return content, False


def _pr_labels_from_event():
    event_path = env("GITHUB_EVENT_PATH")
    if event_path and os.path.isfile(event_path):
        try:
            with open(event_path, "r", encoding="utf-8") as fh:
                event = json.load(fh)
            pr = event.get("pull_request") or {}
            return [lbl.get("name") for lbl in (pr.get("labels") or []) if lbl.get("name")]
        except (OSError, ValueError):
            pass
    return []


def maybe_open_autofix_pr(findings, repo_root):
    """If the PR carries the opt-in label, apply only the auto-fixable findings
    and open a SEPARATE pull request for review. Nothing is ever merged
    automatically — the developer reviews and merges the fix PR themselves."""
    label = env("INPUT_AUTOFIX_LABEL", "iac-autofix")
    if not label:
        return
    if label not in _pr_labels_from_event():
        log(f"auto-fix label '{label}' not present — suggestions only, nothing applied.")
        return

    fixes = [f for f in findings if f.get("auto_fixable") and f.get("fix")]
    if not fixes:
        log("auto-fix label present, but no auto-fixable findings to apply.")
        return

    changed_files = []
    applied = []
    for f in fixes:
        fx = f["fix"]
        rel = fx.get("file")
        if not rel:
            continue
        path = os.path.join(repo_root, rel)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
        new_content, changed = apply_attribute_fix(
            content, fx.get("resource_address"), fx.get("attribute"), fx.get("value")
        )
        if changed:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new_content)
            if rel not in changed_files:
                changed_files.append(rel)
            applied.append(f)

    if not changed_files:
        log("auto-fix label present, but no files needed changes.")
        return
    _open_fix_pr(changed_files, applied)


def _open_fix_pr(changed_files, applied):
    repo = env("GITHUB_REPOSITORY")
    gh_token = env("INPUT_GITHUB_TOKEN") or env("GITHUB_TOKEN")
    head_ref = env("GITHUB_HEAD_REF")  # the PR's source branch
    pr_number = env("INPUT_PR_NUMBER") or _pr_number_from_event()
    if not (repo and gh_token and head_ref):
        log("cannot open auto-fix PR (missing repo / token / head ref).")
        return

    branch = f"sovereign/autofix-{pr_number or 'pr'}"
    subprocess.run(["git", "config", "user.email", "actions@users.noreply.github.com"], cwd=None, check=False)
    subprocess.run(["git", "config", "user.name", "sovereign-iac-bot"], check=False)
    subprocess.run(["git", "checkout", "-B", branch], check=False)
    subprocess.run(["git", "add", *changed_files], check=False)
    subprocess.run(["git", "commit", "-m", "Apply Sovereign IaC auto-fixes"], check=False)
    push_url = f"https://x-access-token:{gh_token}@github.com/{repo}.git"
    push = subprocess.run(["git", "push", "--force", push_url, f"HEAD:refs/heads/{branch}"],
                          capture_output=True, text=True)
    if push.returncode != 0:
        log(f"auto-fix branch push failed: {(push.stderr or '')[:300]}")
        return

    api = env("GITHUB_API_URL", "https://api.github.com")
    body = ["### 🛠️ Sovereign IaC auto-fixes",
            "",
            "Static, unambiguous fixes applied for your review. **Nothing is merged "
            "automatically** — review and merge this PR to apply them.",
            "",
            "| File | Finding | Change |", "|---|---|---|"]
    for f in applied:
        fx = f["fix"]
        body.append(f"| `{fx['file']}` | {f.get('title','')} | `{fx['attribute']} = {fx['value']}` |")
    payload = {"title": "Sovereign IaC auto-fixes (review & merge)",
               "head": branch, "base": head_ref, "body": "\n".join(body)}
    try:
        pr = _gh_request("POST", f"{api}/repos/{repo}/pulls", gh_token, payload)
        if pr and pr.get("html_url"):
            log(f"opened auto-fix PR for review: {pr['html_url']}")
        else:
            log("auto-fix PR request returned no URL (it may already exist).")
    except Exception as e:  # noqa: BLE001 - best effort
        log(f"could not open auto-fix PR: {e}")


# ── main ────────────────────────────────────────────────────────────────────
def main() -> int:
    api_url = env("INPUT_API_URL")
    token = env("INPUT_TOKEN")
    if not api_url:
        fail("api-url input is required")
    if not token:
        fail("token input is required (set it from a secret)")

    repo_root = env("GITHUB_WORKSPACE") or os.getcwd()
    workdir = env("INPUT_WORKING_DIRECTORY") or repo_root
    if not os.path.isabs(workdir):
        workdir = os.path.join(repo_root, workdir)
    fail_on = (env("INPUT_FAIL_ON", "CRITICAL")).upper()

    log(f"working directory: {workdir}")
    plan = load_plan_json(workdir)
    tf_sources = collect_tf_sources(workdir, repo_root)
    changed = collect_changed_files(repo_root)
    log(f"collected {len(tf_sources)} .tf source file(s); {len(changed)} changed in PR")

    if not tf_sources and not plan:
        fail(
            "nothing to scan: no .tf sources found under "
            f"'{workdir}' and no Terraform plan available."
        )

    body = {
        "plan_json": plan,
        "tf_sources": tf_sources,
        "changed_files": changed,
        "fail_on": fail_on,
        "repo": env("GITHUB_REPOSITORY"),
        "pr_number": env("INPUT_PR_NUMBER") or _pr_number_from_event(),
        "commit_sha": env("GITHUB_SHA"),
    }

    result = call_scan_api(api_url, token, body)

    summary = result.get("summary", {})
    blockers = result.get("blocker_count", 0)
    should_block = result.get("should_block", False)
    gh = result.get("github", {}) or {}

    log(
        "results: "
        f"{summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
        f"{summary.get('medium', 0)} medium, {summary.get('low', 0)} low "
        f"({result.get('annotated_count', 0)} anchored to a line)"
    )

    emit_annotations(gh.get("annotations") or [])
    markdown = gh.get("summary_markdown") or "Sovereign IaC scan completed."
    write_step_summary(markdown)
    upsert_pr_comment(markdown)

    # Opt-in only: if the PR carries the auto-fix label, open a SEPARATE PR with
    # the safe fixes applied for review. Default behaviour (no label) is
    # suggestions only — nothing is ever applied or merged automatically.
    try:
        maybe_open_autofix_pr(result.get("findings") or [], repo_root)
    except Exception as e:  # noqa: BLE001 - auto-fix is best-effort, never fails the gate
        log(f"auto-fix step skipped due to error: {e}")

    # Expose machine-readable outputs for downstream steps.
    out_path = env("GITHUB_OUTPUT")
    if out_path:
        try:
            with open(out_path, "a", encoding="utf-8") as fh:
                fh.write(f"should_block={'true' if should_block else 'false'}\n")
                fh.write(f"blocker_count={blockers}\n")
                fh.write(f"critical={summary.get('critical', 0)}\n")
                fh.write(f"high={summary.get('high', 0)}\n")
        except OSError:
            pass

    if should_block:
        fail(
            f"{blockers} finding(s) at or above {fail_on} — failing the check. "
            "See the PR comment for fixes.",
            code=1,
        )
    log("no blocking findings — gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
