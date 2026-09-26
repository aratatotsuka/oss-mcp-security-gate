# OSS / MCP Security Gate

導入前のOSSとMCP JSON snapshotを静的検査し、OPAで `ALLOW` / `REVIEW` / `BLOCK` / `ERROR` を判定するfail-closed CLIです。

> Scanner is untrusted. Target is hostile. Network is denied unless explicitly required. A failed or incomplete scan must never become ALLOW.

本ツールは「安全証明」を行いません。固定・検証済みScanner、鮮度を確認したDB、隔離されたLinux workerという条件の下で、既知脆弱性、Secret、設定不備、Supply Chain posture、MCP static/YARA signalを集めます。非検出は未知の脆弱性や実行時挙動がないことを意味しません。

## MVP scope

- OSV-Scanner 2.6.0: dependency/CVE/GHSA（offline DB、`fix`禁止）
- Trivy 0.74.0: filesystem vulnerability/misconfiguration/secret補助（update禁止、plugin禁止）
- Gitleaks 8.30.1: Secret（100% redact後に再mask）
- OpenSSF Scorecard 5.2.1: supply-chain posture（専用GitHub-only egress workerがある場合のみ）
- Cisco MCP Scanner 4.8.4: pre-generated JSONに対するstatic/YARAだけ
- OPA 1.20.2: local CLI policy evaluation

Syft、Grype、Semgrep、Falco、Snyk、外部LLM、VirusTotal、Cisco cloud API、live MCP、target build/install/test/scriptはMVPに含めません。

## Build

開発環境の前提条件、Windows/Linux別の初回手順、テスト、実スキャン用workerの準備は[環境構築手順](docs/environment-setup.md)を参照してください。開発用OPA CLIの導入手順は1.21.0、実スキャン用の承認済みartifactは1.20.2です。Go 1.24以上を使います。moduleに第三者Go dependencyはありません。

```bash
go test ./...
opa test policies --fail-on-empty
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/security-gate ./cmd/security-gate
```

`go test ./...`、`opa test policies --fail-on-empty`、`go vet ./...`で開発用の検証を行います。

## Provisioning is mandatory

配布物の `config/scanners.yaml` にある64桁ゼロのworker digestは、未provisionを明示するsentinelです。この状態でscanは `UNSUPPORTED_SECURITY_REQUIREMENT` となり、ALLOWにはなりません。

Update workerで次を完了してから、承認済みmanifestをScan workerへ配布してください。

1. `scripts/update-security-data.ps1 -Scanner osv-scanner` で計画を確認する。
2. `-Execute` はquarantineへ取得しSHA-256だけを検証する。Scan workerでは実行しない。
3. Scannerごとの署名/provenanceとSecurity Advisoryを確認する。
4. 固定artifactからnon-root worker imageを再現可能に作成し、内部registryへmirrorする。
5. image digestを `worker_image` に記録する。tagだけは禁止。
6. offline DB/check bundleを別pipelineで取得・検証し、read-only cacheとして配布する。
7. `security-gate verify-scanners` がすべて成功することを確認する。

更新手順の詳細は `docs/detailed-design.md` を参照してください。設定をtarget repositoryに置かず、Security Gateの管理repositoryから配布します。

## CLI

```bash
security-gate verify-scanners --root /opt/security-gate

security-gate scan --root /opt/security-gate --target ./target --type oss \
  --output ./security-gate-report.json

security-gate scan --root /opt/security-gate --target ./snapshots --type mcp-static \
  --tools ./snapshots/tools.json \
  --prompts ./snapshots/prompts.json \
  --resources ./snapshots/resources.json

security-gate policy-check --root /opt/security-gate ./policy-input.json
```

`scan ./target` も利用できます。MCP snapshotは必ず`--target`配下に置きます。CLIは対象コード、package manager、Dockerfile、Makefile、Git hookを実行しません。

Exit codeは `0=ALLOW`, `2=REVIEW`, `3=BLOCK`, `4=ERROR`, `64=usage error` です。

## Isolation contract

各offline scannerは次のDocker条件で起動されます。

- `--pull never`, digest-pinned image, `--network none`
- non-root UID/GID 65532、read-only root filesystem
- target read-only、capabilities ALL DROP、no-new-privileges
- CPU/memory/PID/timeout/output/tmpfs limit
- credential/proxy environmentを継承しない
- Docker/containerd socket、host filesystem、host namespaceをmountしない

ScorecardはFQDN allowlistを強制できる外部proxy/firewallがない場合、実行を拒否します。Docker network名だけを「制限」とみなすことはしません。

## Results and audit

reportは共通Finding、scan completeness、Scanner version/digest、policy version、decision、reason、exception、SHA-256を含みます。Secret候補はparser直後とreport書込直前の二段階でmaskします。raw scanner outputは保存しません。

auditは`var/audit/audit.jsonl`へ0600で追記し、前record hashを含むhash chainにします。source全文、secret、token、credentialは記録しません。

## Exceptions

`config/exceptions.example.json`を参考に、Security Gate管理領域に置きます。finding ID、理由、approver、作成・失効日時、scope、evidenceがすべて必須です。期限切れは自動的に無効です。Secret、integrity、prohibited capability、MCP YARAはexceptionで自動ALLOWにできません。

## Important limitations

- 公式artifactと実worker imageはこのsource treeに同梱していません。
- 公式image digestを使うlocal E2Eは実施済みですが、本番では承認済みinternal immutable registryへmirrorしたworker imageだけを許可してください。
- static/YARAは難読化・未知のMCP poisoning・実行時rug pullを見逃し得ます。
- lockfileがない、unsupported ecosystem、DBが古い、scannerが失敗した状態はALLOWになりません。
- Windowsは開発・unit test用途です。本番sandbox guaranteeはhardening済みLinux workerを基準にします。

詳細は [初心者向け5W1H](docs/security-5w1h.md)、[詳細設計](docs/detailed-design.md)、[検証結果](docs/verification-report.md)、[Security Policy](SECURITY.md)、[Blocked Security Requirements](BLOCKED_SECURITY_REQUIREMENTS.md) を参照してください。
