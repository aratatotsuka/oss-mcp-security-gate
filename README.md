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
- OPA 1.20.2: local CLI / Linux container policy evaluation

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

OSS用の4製品とoffline DBをまとめて準備するには、次を実行します。`npm`はJavaScript/TypeScript用で、Goなら`Go`、Pythonなら`PyPI`を指定します。

```powershell
.\scripts\deploy-oss.ps1 -PrepareOnly -Ecosystem npm
# 公式HTTPSのdigest照合方式を採用して通常設定へ反映する場合
.\scripts\deploy-oss.ps1 -Ecosystem npm -AcceptOfficialDigestPolicy
.\scripts\scan-oss.ps1 -Target 'var/targets/nulab/backlog-mcp-server'
```

取得済みartifactの再利用、Docker image作成、OPA・版確認、DB取得と全ファイルhash検証を自動化しました。WindowsでもDocker Linux engine上で実行できます。**署名・build provenance・DB publisher署名は検証しません。** 通常反映には上記方式の明示選択が必要です。詳しくは[OSS配備と実行](docs/oss-deployment.md)を参照してください。以下は署名・provenanceを必須とする組織向けの手順です。

配布物の `config/scanners.yaml` にある64桁ゼロのworker digestは、未provisionを明示するsentinelです。この状態でscanは `UNSUPPORTED_SECURITY_REQUIREMENT` となり、ALLOWにはなりません。

Update workerで次を完了してから、承認済みmanifestをScan workerへ配布してください。

固定版と公式配布元の最新版を比較するには、`.\scripts\check-scanner-versions.ps1`を実行します。最新版の候補取得と承認後の反映は[検証ツールの版を更新する](docs/scanner-version-update.md)に従って`.\scripts\update-scanner-versions.ps1`を使います。
OPAの本番用自動更新は、LinuxのUpdate workerで`pwsh ./scripts/update-scanner-versions.ps1 -Mode Auto -Scanner opa`を実行します。必要な検証が失敗した場合は反映しません。条件は[更新手順](docs/scanner-version-update.md)を参照してください。

1. `scripts/update-security-data.ps1 -Scanner osv-scanner` で計画を確認する。
2. `-Execute` はquarantineへ取得しSHA-256だけを検証する。Scan workerでは実行しない。
3. Scannerごとの署名/provenanceとSecurity Advisoryを確認する。
4. 固定artifactからnon-root worker imageを再現可能に作成し、内部registryへmirrorする。
5. image digestを `worker_image` に記録する。tagだけは禁止。
6. offline DB/check bundleを別pipelineで取得・検証し、read-only cacheとして配布する。
7. `security-gate verify-scanners` がすべて成功することを確認する。

取得から配備・検証までの手順と現時点の未完了箇所は[環境構築手順](docs/environment-setup.md#6-実スキャン用の配備)を参照してください。設定をtarget repositoryに置かず、Security Gateの管理repositoryから配布します。

## CLI

PowerShellで入力を減らして実行する場合は、リポジトリのルートから次を使います。スクリプトはCLIがないかGoソースより古い場合、実行前に再ビルドします。レポートは既定で `var/reports/<検証種別>/<対象>/<実行日時>/report.json` と同じフォルダのHTML・Markdown・CSVへ出力し、実行ごとに分けます。`-Output` でJSONの出力先を明示した場合はその場所を使います。GitHub URL指定時は `var/targets` に新規cloneし、取得したcommit IDを表示します。既存の取得先は上書きしません。`-Commit` には固定した40桁のcommit IDを指定できます。

```powershell
.\scripts\scan-oss.ps1 -RepositoryUrl 'https://github.com/nulab/backlog-mcp-server'
# 取得済みのディレクトリを検査する場合
.\scripts\scan-oss.ps1 -Target 'var/targets/nulab/backlog-mcp-server'
```

### MCP snapshot preparation

`var/targets/nulab/backlog-mcp-server` は取得したソースコードです。MCP静的検査に使う `var/targets/backlog-mcp-snapshot` と `tools.json` は、別途用意する入力です。ディレクトリを作るだけでは検査できません。隔離した環境のMCPクライアントで対象サーバーの `tools/list` を取得し、実際の応答を `{"tools":[...]}` 形式のJSONファイルとして保存してください。APIキーやツール実行結果をこのファイルに含めないでください。Security Gate自身はサーバー起動・接続・snapshot取得を行いません。

既に取得済みのツール一覧JSONがある場合は、`-ToolsSource` に渡します。スクリプトが `-SnapshotDir` のディレクトリを作成し、JSONを `tools.json` として配置してから検査します。`<取得済みtools.jsonのパス>` は実在するファイルに置き換えてください。既存の `tools.json` は上書きしません。テスト用の `tests/e2e/fixtures/mcp/tools.json` はBacklogの定義ではありません。

```powershell
.\scripts\scan-mcp-snapshot.ps1 -ToolsSource '<取得済みtools.jsonのパス>' -SnapshotDir 'var/targets/backlog-mcp-snapshot'
```

保存済みのsnapshotを再検査する場合は `-ToolsSource` を省略します。`Tools` は既定で `tools.json`、`Prompts` と `Resources` は必要な場合だけ指定します。snapshotがない場合、ディレクトリは作成されますが検査は開始せず、必要なファイルを示すエラーになります。

```powershell
.\scripts\scan-mcp-snapshot.ps1 -SnapshotDir 'var/targets/backlog-mcp-snapshot'
```

両スクリプトともCLIの判定終了コード（`0/2/3/4`）を返します。実スキャンには上記の承認済みscannerとworkerの配備が必要です。`--repo` を指定するScorecard検査は専用通信制限環境が未配備のため含めていません。

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

スクリプトの `report.json` は判定の正本です。同じ実行フォルダに
`report.html`、`report.md`、`report-findings.csv`、
`report-review-required.csv` も出力します。HTMLはオフラインで開けます。
HTMLとMarkdownには総合判定、理由、scannerの実行状態、severity別件数、検出事項を表示します。
要確認CSVは重大度や不完全な検出事項を抽出した調査用一覧で、個々のpolicy判定ではありません。
scannerの失敗は検出事項が0件でも総合判定と実行状態で確認してください。


reportは共通Finding、scan completeness、Scanner version/digest、policy version、decision、reason、exception、SHA-256を含みます。Secret候補はparser直後とreport書込直前の二段階でmaskします。raw scanner outputは保存しません。

auditは`var/audit/audit.jsonl`へ0600で追記し、前record hashを含むhash chainにします。source全文、secret、token、credentialは記録しません。

## Exceptions

`config/exceptions.example.json`を参考に、Security Gate管理領域に置きます。finding ID、理由、approver、作成・失効日時、scope、evidenceがすべて必須です。期限切れは自動的に無効です。Secret、integrity、prohibited capability、MCP YARAはexceptionで自動ALLOWにできません。

## Important limitations

- 公式artifactと実worker imageはこのsource treeに同梱していません。
- 公式HTTPS digest照合によるローカルOSS配備を追加しました。署名・provenance必須の本番環境では追加検証とinternal registryへのadmissionが必要です。
- static/YARAは難読化・未知のMCP poisoning・実行時rug pullを見逃し得ます。
- lockfileがない、unsupported ecosystem、DBが古い、scannerが失敗した状態はALLOWになりません。
- WindowsからDocker Linux engineでOSS実スキャンできます。本番sandbox guaranteeはhardening済みLinux workerを基準にします。

詳細は [初心者向け5W1H](docs/security-5w1h.md)、[詳細設計](docs/detailed-design.md)、[検証結果](docs/verification-report.md)、[Security Policy](SECURITY.md)、[Blocked Security Requirements](BLOCKED_SECURITY_REQUIREMENTS.md) を参照してください。
