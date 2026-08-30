# Test fixtures

Copies of `demo-iac-pr/main.tf` and `main.fixed.tf`, the pair the GitHub Action
smoke test and the demo recording also use.

They live here rather than being read from the monorepo so this package's tests
run in a standalone checkout — the public MCP repository does not contain
`demo-iac-pr/`. `test_scan_golden.py` asserts the known finding set, so drift
between these copies and the originals shows up as a test failure rather than
silently.
