# Verification Report

実施日: 2026-09-24

対象version: 1.0.0

## Automated results

| Check | Result |
|---|---|
| `go vet ./...` | PASS |
| `go test -count=1 ./...` | PASS（parser/normalizer/policy/masking/expiry/timeout/output limit/integrity/audit/sandbox/security negative tests） |
| GoからOPA CLIを呼ぶintegration test | PASS（OPA 1.20.2、ALLOW結果のparseを確認） |
| `opa test policies --fail-on-empty` | PASS 7/7 |
| JSON manifest/schema parse | PASS |
| Windows amd64 build | PASS |
| Linux amd64 static cross-build (`CGO_ENABLED=0`) | PASS |
| Third-party Go module | なし（`go list -m all`は本moduleのみ） |
| 未provision状態のscan | PASS: decision `ERROR`, exit 4、3 Scannerすべてintegrity failure。ALLOWにならない |
| Runtime container isolation | PASS（digest固定BusyBox、`network=none`、read-only、UID/GID 65532、全capability drop、no-new-privileges、socket非公開、metadata/public Internet遮断、対象hash不変） |
| OSV-Scanner 2.6.0 real offline scan | PASS（offline DBからlodash 4.17.20の5脆弱性を検出） |
| Trivy 0.74.0 real offline scan | PASS（5脆弱性、2 misconfiguration、1 secretを検出。DB/check update無効、network=none） |
| Gitleaks 8.30.1 real offline scan | PASS（無効なfixture tokenを1件検出、Match/Secretは完全redact） |
| Real output normalize + native/OPA policy | PASS（14 findings: vulnerability 10 / misconfiguration 2 / secret 2、両方とも`BLOCK`） |
| Update/Scan worker separation | PASS（Trivy updateはtarget非mount、OSV updateは空directoryのみ。実targetはnetwork=none scan workerだけにmount） |

## Binary digests

- `bin/security-gate.exe`: `sha256:3fd76f4d9ad439978fb829f2ef86c68b77650d882c86ee6cda04e8d8ed2ec580`
- `bin/security-gate-linux-amd64`: `sha256:02136e6d7d3a2b63e57c5c60ca4e5219066d6bf594d3335a6a6166748b4384b2`

## Docker artifacts used by E2E

- OSV-Scanner: `ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa`
- Trivy: `aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969`
- Gitleaks: `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`
- Runtime probe: `busybox@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092`

Raw E2E JSONは`var/e2e-output/`、DB cacheは`var/e2e-cache/`へ生成した（いずれも`.gitignore`対象）。実出力のSHA-256はOSV `0fbf27bfe84d810e1e2d9778fba35bed16c6818719d739b465444fa742c23760`、Trivy `4f0a80dcf01935355b734d880900b80de6fc8aeb4c8cb71a725200b107c599a7`、Gitleaks `26e16ac6c95557611251ce09f3124245fa211651c80a31c5f85d3735163162c7`。

## Defects found and corrected by E2E

- Gitleaks 8.30.1が空の`[allowlist]`を拒否したため、allowlist自体を定義しない管理設定へ修正した。target側configは引き続き読まない。
- OSV 2.6.0のCVSS vector文字列を数値として扱ってseverityが`UNKNOWN`になる問題を修正し、`database_specific.severity`を優先するreal-shape regression testを追加した。

## Not executed

- Cisco MCP Scanner real E2E: 4.8.4 wheelのPyPI provenance/hashは確認済みだが、transitive dependency hash lockと承認済みbase imageが未確定のため未実行。安全条件を弱めていない。
- Scorecard real E2E: GitHubだけに通信先を強制するFQDN-aware proxy/firewallがないため未実行。通常のDocker bridgeを制限付きegressとは扱わない。
- Production internal worker image admission: 上記は公式image digestを直接使ったE2Eであり、組織内immutable registryへのmirror/admissionは未実施。配布manifestのzero digest sentinelは維持する。
- Go race detector: このWindows環境では`-race`がcgoを要求し、C toolchainがないため未実施。通常testとvetは合格。

未実施項目を成功扱いせず、`BLOCKED_SECURITY_REQUIREMENTS.md`に記録している。

## 2026-09-26 再実行結果

環境: Windows amd64、Go 1.27.1、開発用OPA CLI 1.21.0、Docker Linux engine 29.8.0。`OPA_TEST_BIN`と既存の`var/e2e-output`を指定して実行した。

| テスト | 結果 |
| --- | --- |
| `opa test policies --fail-on-empty` | PASS 9/9（OPA 1.21.0） |
| `go test -count=1 ./...` | 2件失敗: `TestLoadRejectsMalformedWorkerDigest`、`TestRejectMalformedImageDigest`。他のテスト対象パッケージはPASS |
| `go test -count=1 -v ./tests -run TestRealScannerOutputsNormalizeAndBlock` | PASS。保存済み実scanner JSONから14 findings、判定`BLOCK`。scannerの新規起動は含まない |
| `go test -count=1 -v ./internal/policy -run TestEvaluateOPA` | PASS。GoからOPA 1.21.0を呼ぶ連携テスト |
| `go vet ./...` | PASS |
| `tests/runtime-isolation.ps1` | PASS。digest固定BusyBoxでtarget書込・外部通信を拒否し、対象hash不変を確認 |
| `go test -race -run '^$' ./internal/manifest` | 実行不可。`CGO_ENABLED=1`で再試行したがC compiler `gcc`が見つからずbuild失敗 |

Cisco MCP Scanner、Scorecard、本番用内部worker imageのE2Eは、上記の配備・承認条件がまだ満たされておらず未実施。実scannerの新規Docker実行も今回の再実行には含めていない。配布manifestのOPAは引き続き1.20.2で、1.21.0の本番用admissionは行っていない。

### 初回公開前の再検証

2026-09-26、不正なimage digestの形式検証を修正し、Go module名を`github.com/aratatotsuka/oss-mcp-security-gate`へ変更した。`OPA_TEST_BIN`と保存済み実scanner出力を指定した`go test -count=1 ./...`は全パッケージPASS。`go vet ./...`とOPA 1.21.0の`opa test policies --fail-on-empty`（9/9）もPASS。上表のGoテスト2件失敗は修正前の結果である。
