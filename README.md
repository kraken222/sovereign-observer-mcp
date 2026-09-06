# Sovereign MCP

Your AI assistant writes Terraform. This checks it before you do.

An MCP server that scans Terraform for security misconfigurations **while the code is
being generated**, not after it lands in a pull request. It runs locally, needs no
account, and your infrastructure code never leaves your machine.

Detection is [Checkov](https://github.com/bridgecrewio/checkov) (Apache-2.0), vendored so
it runs offline and pinned to the same version the backend evaluates. What this adds is
the shape around it: findings compact enough to sit in an assistant's context, curated
remediation per check, a narrow allowlist of fixes that are safe to apply mechanically,
hardened templates and org policy served *before* generation, and a handful of checks
Checkov does not cover — a credential written as a literal in the HCL among them.

```
You:       "add an RDS instance for the orders service"
Assistant: [writes HCL] → [scans it] → [fixes 4 findings] → shows you the result
```

---

## Why this exists

Provider defaults optimise for *it works*, not *it is safe*. Terraform generated from a
model's memory is routinely unencrypted, publicly reachable, or missing deletion
protection — and the cost of fixing that rises steeply the further it travels. In the
editor it is one attribute. In a PR it is a review cycle. In production it is an incident.

CI already catches this. CI catches it three days and one argument later.

---

## Install

### Claude Code

```bash
claude mcp add sovereign -- uvx sovereign-observer
```

### Cursor

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "sovereign": {
      "command": "uvx",
      "args": ["sovereign-observer"]
    }
  }
}
```

### VS Code (GitHub Copilot)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "sovereign": {
      "type": "stdio",
      "command": "uvx",
      "args": ["sovereign-observer"]
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "sovereign": {
      "command": "uvx",
      "args": ["sovereign-observer"]
    }
  }
}
```

First run downloads the engine (~100 MB) and takes a moment. After that it is local and
fast.

---

## Environments

A scanner that reports the same severity everywhere gets muted. Multi-AZ and deletion
protection are the right call in production and noise on a sandbox torn down nightly, and
once someone has dismissed the same Critical five times on a scratch stack they stop
reading the output at all.

So every finding is tagged with the environment it was inferred to belong to, from an
`Environment` tag or the directory the file sits in. `unknown` is a normal answer and
changes nothing.

Passing `environment_aware` to `scan_terraform` lets that inference move severity — but
only for an explicit allowlist of resilience, monitoring and housekeeping checks. **Public
access, encryption, identity and hardcoded credentials never move, in any environment.** A
dev bucket is usually where last month's production dump lives.

It is off by default, because a scan that quietly drops a finding below the level your
merge gate keys on has weakened your pipeline without asking. Nothing is ever lowered
below `Low`, and a finding that moved says what it moved from.

---

## Tools

| Tool | What it does |
|---|---|
| `scan_terraform` | Scan HCL — from disk or an unsaved buffer. Returns findings by severity with file and line, each tagged with its inferred environment. |
| `explain_finding` | The full remediation for one finding: what is wrong and the exact Terraform to fix it. |
| `apply_fixes` | Apply the mechanically-safe fixes and return patched HCL. |
| `secure_template` | A hardened starting point for a resource type, so the insecure version never gets written. |
| `check_compliance` | Map findings to SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA, NIS2, NCA (Saudi), NESA (UAE). |
| `framework_coverage` | Which articles of a regulation automated scanning can and cannot evidence. |
| `org_requirements` | Your organization's own rules for a resource type — *before* the code is written. |
| `org_status` | Whether org policy is in force, or built-in rules only. |

You do not call these. The assistant does, on its own, because the server tells it to.

---

## Organization policy

Everything above works with no account. Connecting an organization adds **your
company's own rules** to the same local evaluation:

```bash
export SOVEREIGN_TOKEN=...   # Integrations → GitHub in the dashboard
```

The difference this makes is in *when* the rule applies. Without it, the assistant writes
Terraform and then finds out it was wrong. With it:

```
You:       "add an RDS instance for the orders service"
Assistant: → org_requirements("aws_db_instance")
           ← "backup_retention_period must be at least 365"
             "region must be one of: eu-west-1, eu-central-1"
           [writes Terraform that already satisfies both]
           → scan_terraform → clean
```

The rule is supplied to the generator, not applied to the output. That is the whole point
— a violation that never gets written costs nothing to fix.

Company rules appear in scans tagged `source: org_policy`, so a developer can always tell
a company requirement from a built-in one. They are authored in the dashboard as YAML and
enforced identically in the editor, in CI, and in a cloud scan.

**This does not change what leaves your machine.** Rules come down; code never goes up.
The only request this server makes is a `GET` for your org's rules —
`tests/test_org_policy.py::test_no_terraform_is_ever_uploaded` asserts that at the
transport, and asserts an unconnected install opens no socket at all. If the API is
unreachable or the token is rejected, the built-in rules still run locally and the scan
still works.

---

## What it does not do

Worth stating plainly, because a security tool that overstates its scope is worse than no
tool:

- **It is not a compliance assessment.** `check_compliance` returns control *mappings* —
  evidence that shortens an audit. Every framework it maps also carries governance,
  process and training obligations no configuration scanner can observe. A clean scan is
  not a compliant organisation.
- **NCA control identifiers are provisional**, pending reconciliation against the
  authority's published catalogue. Cite the subdomain names.
- **`apply_fixes` is deliberately narrow.** It applies only single-attribute, in-place
  changes from a hand-verified allowlist, and never overwrites a value wired to a variable
  or expression. Everything else stays advisory, because a mechanical fix that is
  syntactically clean can still take a running system down.
- **It scans Terraform**, not live cloud accounts, container images, or dependencies.

For live multi-cloud posture management, attack-path analysis and audit-ready reporting,
this is the editor-side slice of [Sovereign Observer](https://sovereign-observer.com).

---

## Privacy

The scan runs in this process, on your machine. There is no API key, no account, and no
network call in the default path — the server works with networking disabled. Your
Terraform is never uploaded.

---

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

`sovereign_mcp/_vendor/` holds the IaC engine. In the Sovereign Observer
monorepo those modules are generated at build time by `scripts/vendor_engine.py`
so the rule logic has exactly one source; here they are committed so this
package builds on its own. **Edit them upstream, not here** — changes made in
this repository are overwritten on the next sync.

`tests/test_parity.py` verifies the vendored copies match their upstream source
and that the Checkov pin matches the backend's. Those checks skip automatically
outside the monorepo, since there is nothing to compare against.

Licensed Apache-2.0. Built on [Checkov](https://github.com/bridgecrewio/checkov)
(Apache-2.0).
