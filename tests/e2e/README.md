# E2E fixtures

These files are deliberately vulnerable test data. Credentials are non-working public examples and must never be replaced by real values. Tests must mount this directory read-only and must not execute its Dockerfile or package manager metadata.

The verified local run used digest-pinned OSV-Scanner 2.6.0, Trivy 0.74.0, and Gitleaks 8.30.1 containers. DB download/update workers had network access but no real target mount. Scan workers mounted the target read-only with `--network none`, a read-only root filesystem, UID/GID 65532, all capabilities dropped, and `no-new-privileges`.

After the real scanners write JSON under ignored `var/e2e-output`, run the normalization/policy E2E with:

```powershell
$env:SECURITY_GATE_REAL_E2E_DIR = "<project>\var\e2e-output"
$env:OPA_TEST_BIN = "<verified opa_windows_amd64.exe>"
go test -v ./tests -run TestRealScannerOutputsNormalizeAndBlock
```

The expected result is 14 normalized findings and a `BLOCK` decision from both the native reference evaluator and OPA.
