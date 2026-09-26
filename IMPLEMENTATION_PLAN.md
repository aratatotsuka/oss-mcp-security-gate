# OSS / MCP Security Gate Implementation Plan

確認日: 2026-09-24

## 現状

- 新規リポジトリ。既存コード、既存技術スタック、参考Excelは存在しない。
- 要件は添付テキストを正とし、一次情報で補正する。
- 実行環境にはGitとDocker CLIがあるが、Go/OPAは未導入、Docker daemonは停止中。
- 本実装はGo標準ライブラリのみで構築し、アプリ自身の第三者Go依存を持たない。

## 実装対象

- `security-gate scan`, `verify-scanners`, `policy-check` CLI。
- hostile targetを実行しない静的scan orchestration。
- Scanner manifest、SHA-256検証、version照合、fail-closed。
- Docker用default-deny sandbox command builder。
- Scanner固有JSON parserと共通Finding normalizer。
- OPA Rego policy、OPA CLI evaluation、policy test。
- 期限必須exception、secret masking、tamper-evident audit record、report hash。
- fixtureによるunit/integration/security negative test。
- update/fetchとscanの分離、運用script、schema、利用者向け文書。

## 使用するScanner

| Scanner | 固定version | MVP用途 | Network |
|---|---:|---|---|
| OSV-Scanner | 2.6.0 | dependency/CVE/GHSA | none |
| Trivy | 0.74.0 | vuln/misconfiguration/secret補助 | none |
| Gitleaks | 8.30.1 | secret | none |
| OpenSSF Scorecard | 5.2.1 | repository posture | GitHub API限定worker |
| Cisco MCP Scanner | 4.8.4 | static/YARAのみ | none |
| OPA | 1.20.2 | local policy evaluation | none |

artifact digestは`config/scanners.yaml`（JSON互換YAML）で必須とする。Update Pipelineが公式checksum、署名/provenance、advisory確認を完了して内部mirror URIとdigestを確定するまでScan Pipelineは実行しない。

## 使用しないScanner / 機能

- Syft、Grype、Semgrep、Falco、Snyk Agent Scan。
- 外部LLM、VirusTotal、Cisco AI Defense API。
- live MCP connection、MCP server/tool実行。
- target build/test/install/script、scanner fix、自動修復。
- Trivy plugin manager、remote module、Docker/containerd socket。

## Security assumptions

- Scannerは侵害され得る。Targetはhostile。Networkは明示許可以外deny。
- Scanner/DB/policy/manifestのintegrityが確認できない状態はALLOWにしない。
- 静的scannerの非検出は安全証明ではない。
- Scan workerはproduction credentialを一切受け取らない。
- Scorecard credentialが必要な場合は専用workerのread-only fine-grained tokenだけを使う。

## Trust boundaries

1. Internet → Update/Fetch Worker
2. Update/Fetch Worker → quarantine/verification
3. Verified artifact → Internal Scanner Cache
4. Cache/Target(read-only) → isolated Scan Worker
5. raw scanner output → Finding Normalizer
6. normalized input → local OPA
7. signed/hash-linked result → Result/Audit Store

## 実装順序

1. model/schemaとmanifest integrity verification。
2. sandbox command builder、bounded subprocess runner。
3. scanner adapters/parser、normalizer、masking。
4. exception/audit/report。
5. Rego policyとOPA adapter。
6. orchestratorとCLI。
7. unit/integration/security tests。
8. 5W1H、詳細設計、README、SECURITY。
9. test/build、最終配置。

## Risk

- upstream JSON schema/CLI option変更: version固定とfixture contract testで検知する。
- malicious outputによるmemory/disk枯渇: byte limit、timeout、PIDs/memory/CPU/tmpfs limit。
- secret再漏洩: parser直後にmaskし、raw outputは永続化しない。
- scanner compromise: hash/version/provenance gate、network deny、read-only、cap-drop。
- false negative: completeness statusとmanual review criteriaをreportへ残す。
- Docker自体の権限: socketをworkerへ渡さず、daemon運用権限を別管理する。

## Unresolved issues / BLOCKED_SECURITY_REQUIREMENT

- 公式artifactを実際に取得・検証して内部mirrorへ登録する組織環境は未提供。`update-security-data`は手順と検証入口を実装するが、mirror登録は運用者承認が必要。
- Docker daemonが現在停止中のため、実scanner containerのend-to-end testはこの端末では未実施となり得る。
- OS-level egress denyの保証はDocker `--network none`に依存する。ScorecardのGitHub限定egressはDocker単体では宛先FQDN制限を保証できないため、専用proxy/firewallがない場合は`UNSUPPORTED_SECURITY_REQUIREMENT`とする。
- Windows Docker Desktopではproduction Linuxと同一のnamespace/seccomp保証を証明できない。本番はhardening済みLinux runnerを必須とする。

unsafe workaroundは実装しない。上記が満たされないscanは`UNSUPPORTED`/`ERROR`としてALLOWを禁止する。
