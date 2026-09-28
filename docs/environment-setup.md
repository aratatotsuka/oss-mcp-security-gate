# 環境構築手順

この手順は、ソースからCLIをビルドして開発・ポリシーテストを実行するところまでと、実スキャンに必要な配備条件を扱います。コマンドはリポジトリのルートで実行してください。

## 1. 必要なツール

| 用途 | ツール | 確認コマンド |
| --- | --- | --- |
| ソース取得 | Git | `git --version` |
| ビルド・Goテスト | Go 1.24以上 | `go version` |
| 開発用Regoテスト・Go連携テスト | OPA CLI 1.21.0 | `opa version` |
| Windowsの補助スクリプト | Windows PowerShell 5.1以上またはPowerShell 7 | `$PSVersionTable.PSVersion` |
| 実スキャン・隔離テスト | Docker CLIと稼働中のLinux engine | `docker info --format '{{.OSType}}'`（`linux`） |

Goと開発用OPAは実行ファイルを`PATH`から呼べるようにします。Goのツールチェーンはリポジトリ外にインストールします。ここで入れるOPAは`opa test policies --fail-on-empty`と、`OPA_TEST_BIN`を使うGo連携テストのためのものです。**`security-gate scan`と`policy-check`はPATH上のOPAを使いません。** 両コマンドは`config/scanners.yaml`で固定したOPAを使います。`deploy-oss.ps1`で配備した場合はLinuxコンテナで実行し、`worker_image`が空の場合は`runtime_path`の実行ファイルを使います。OPAはCLIのビルドだけなら不要です。Dockerは通常のGo/OPAテストとビルドには不要です。WindowsからもDockerのLinux engine上で実スキャンできます。本番の隔離基盤はhardening済みLinux workerで確認してください。以下のコマンド例はWindows amd64 / Linux amd64向けです。他のCPUでは対応する公式配布物を選んでください。

## 2. ソースを用意する

```bash
git clone '<このリポジトリのURL>' security-gate
cd security-gate
```

既にチェックアウト済みの場合は、リポジトリのルートへ移動します。Goのmoduleは標準ライブラリのみを使用するため、追加のGo依存パッケージをインストールする手順はありません。ローカルの生成物は`bin/`と`var/`に置けます（どちらもGitの無視対象）。

## 3. GoとOPA CLIをインストールする

### Windows

1. [Go公式ダウンロードページ](https://go.dev/dl/)からGo 1.24以上のWindows用MSIを選び、インストーラーを実行します。新しいPowerShellを開いて`go version`でバージョンを確認します。Goの[公式インストール手順](https://go.dev/doc/install)も参照してください。
2. OPA 1.21.0を[公式リリース](https://github.com/open-policy-agent/opa/releases/tag/v1.21.0)から取得し、リリースのSHA-256ファイルと照合します。次のPowerShellブロックは、リポジトリのルートで一括貼り付けできます。取得や照合に失敗した場合は配置せず停止します。

```powershell
& {
    $ErrorActionPreference = 'Stop'
    New-Item -ItemType Directory -Force var | Out-Null
    $opaBase = 'https://github.com/open-policy-agent/opa/releases/download/v1.21.0/opa_windows_amd64.exe'
    Invoke-WebRequest -UseBasicParsing -Uri $opaBase -OutFile var/opa_windows_amd64.exe
    Invoke-WebRequest -UseBasicParsing -Uri "$opaBase.sha256" -OutFile var/opa_windows_amd64.exe.sha256
    $expected = ((Get-Content -Raw var/opa_windows_amd64.exe.sha256).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 var/opa_windows_amd64.exe).Hash.ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$' -or $actual -ne $expected) { throw 'OPA SHA-256 mismatch' }
    $opaDir = Join-Path $HOME 'Tools\OPA'
    New-Item -ItemType Directory -Force $opaDir | Out-Null
    Copy-Item var/opa_windows_amd64.exe (Join-Path $opaDir 'opa.exe')
    $env:Path = "$opaDir;$env:Path"
    opa version
    if ($LASTEXITCODE -ne 0) { throw 'OPA version check failed' }
}
```

`opa version`が`1.21.0`を表示することを確認します。上のブロックの`$env:Path`変更は、実行中のPowerShellでだけ有効です。インストール後に別のPowerShellを開いて`opa`が認識されない場合は、次を実行します。

```powershell
$opaDir = Join-Path $HOME 'Tools\OPA'
$env:Path = "$opaDir;$env:Path"
opa version
```

この`$env:Path`設定は現在のターミナルに限られます。次回以降も使うには、Windowsの「環境変数」→ユーザー環境変数の`Path`に`$HOME\Tools\OPA`の実際の絶対パス（例: `C:\Users\<ユーザー名>\Tools\OPA`）を追加します。VS Codeを使用している場合は、すべてのウィンドウを終了してから起動し直し、新しいPowerShellターミナルで`opa version`を実行してください。「Reload Window」やターミナルの作り直しだけでは、古い`Path`が残る場合があります。

`opa`が認識されないときは、`& (Join-Path $HOME 'Tools\OPA\opa.exe') version`で実行ファイルを直接確認してください。これが動くなら再インストールは不要です。

### Linux

1. [Go公式ダウンロードページ](https://go.dev/dl/)でGo 1.24以上のLinux用アーカイブを取得します。[公式インストール手順](https://go.dev/doc/install)に従い、既存のGoツリーへ上書き展開せず、リポジトリ外へ展開します。ユーザー領域へ新規インストールする例です。

```bash
# ダウンロード済みアーカイブ名に置き換える
go_archive=go1.24.x.linux-amd64.tar.gz
mkdir -p "$HOME/.local"
tar -C "$HOME/.local" -xzf "$go_archive"
export PATH="$HOME/.local/go/bin:$PATH"
go version
```

既に`$HOME/.local/go`がある場合は、公式手順に従って旧ツリーを整理してから展開します。`PATH`設定を次回以降も使うには、使用中のシェルの起動設定へ同じ`export PATH=...`を追加します。

2. OPA 1.21.0のLinux amd64 static binaryとSHA-256ファイルを取得して照合し、ユーザー領域へ配置します。

```bash
mkdir -p var "$HOME/.local/bin"
opa_base=https://github.com/open-policy-agent/opa/releases/download/v1.21.0/opa_linux_amd64_static
curl -fL "$opa_base" -o var/opa_linux_amd64_static
curl -fL "$opa_base.sha256" -o var/opa_linux_amd64_static.sha256
(cd var && sha256sum -c opa_linux_amd64_static.sha256)
install -m 755 var/opa_linux_amd64_static "$HOME/.local/bin/opa"
export PATH="$HOME/.local/bin:$PATH"
opa version
```

`opa version`が`1.21.0`を表示することを確認します。`$HOME/.local/bin`もシェルの起動設定で`PATH`に追加します。OPAの[公式インストール案内](https://www.openpolicyagent.org/docs)も参照してください。

これらは開発用CLIの導入手順です。実スキャンで使うOPA artifactは現在`config/scanners.yaml`で1.20.2に固定されています。1.21.0を本番用に使うには、manifestのversion・URI・SHA-256を更新し、Regoテストと判定結果を検証してから承認済みartifactとして別途配備します。

## 4. 開発環境を確認してテストする

以下はOSごとに該当するコードブロックを一つずつ実行します。PowerShellのテスト用ブロックは一括貼り付けできます。GoテストとRegoテストの結果をそれぞれ確認してください。

PowerShell:

```powershell
go version
opa version
$env:OPA_TEST_BIN = (Get-Command opa).Source
go test ./...
opa test policies --fail-on-empty
```

Linuxのシェル:

```bash
go version
opa version
export OPA_TEST_BIN="$(command -v opa)"
go test ./...
opa test policies --fail-on-empty
```

`OPA_TEST_BIN`はGoのOPA CLI連携テストに使用します。設定しない場合、該当テストはskipされます。PowerShellでは`.\scripts\test.ps1`でも両テストを順に実行できます。このスクリプトは`GOTOOLCHAIN=local`を設定し、Goテストが失敗した場合はRegoテストを実行せず終了します。

`go test ./...`で失敗した場合は表示されたテスト名とエラーを確認してください。[テスト仕様](test-specification.md)には以前の失敗と修正内容も記録しています。

## 5. CLIをビルドする

PowerShell:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    New-Item -ItemType Directory -Force bin | Out-Null
    $env:CGO_ENABLED = '0'
    go build -trimpath -ldflags='-s -w' -o bin/security-gate.exe ./cmd/security-gate
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
    .\bin\security-gate.exe version
    if ($LASTEXITCODE -ne 0) { throw 'CLI version check failed' }
}
```

Linuxのシェル:

```bash
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/security-gate ./cmd/security-gate
./bin/security-gate version
```

`version`の表示は現状`dev`です。ここまででCLIのビルドを確認できます。

## 6. 実スキャン用の配備

**`update-security-data.ps1 -Execute`の次は、`deploy-oss.ps1`を使います。** 取得済みartifactを検証して、Docker image、OSV/Trivyのoffline DB、OPAの実行環境をまとめて用意します。詳しい説明・検証方式・定期更新は[OSS実スキャンの準備と実行](oss-deployment.md)を参照してください。

| 用意するもの | 目的 |
| --- | --- |
| OSV・Trivy・Gitleaks | 依存関係の脆弱性、設定不備、secretを調べる |
| Linux Docker image | 対象を読み取り専用で渡し、通信と権限を制限して実行する |
| OSV/TrivyのDB・checks | スキャン中に通信せず、取得済み情報で検査する |
| OPA Docker image | 検出結果とpolicyから総合判定を出す |

### 6.1 準備モードで確認する

GoとDockerのLinux engineを利用できる状態で、リポジトリのルートから実行します。以下の`npm`はBacklog MCP ServerなどのJavaScript/TypeScript向けです。Goなら`Go`、Pythonなら`PyPI`を指定します。省略時はGoだけです。

```powershell
docker info --format '{{.OSType}}'
.\scripts\deploy-oss.ps1 -PrepareOnly -Ecosystem npm
```

通常のmanifestは変えず、`var/deploy/<実行ID>/prepared-root`に実行環境を作成します。既に取得した4製品のartifactはSHA-256が合えば再利用します。固定版は[manifest](../config/scanners.yaml)に従い、版の更新は[更新手順](scanner-version-update.md)で行います。

**検証範囲:** このスクリプトは公式HTTPS配布元のrelease asset digest照合、Security Advisory差分確認、版・Regoテスト、DB全ファイルのハッシュ記録を行います。署名・build provenance・DBのpublisher署名の検証は行いません。その要件がある環境では[worker admission手順](../workers/README.md)で追加検証が必要です。manifestと配備記録にも未検証と明記し、検証済みとは記録しません。

### 6.2 通常設定へ反映する

上記の検証方式を採用する場合は、次を実行します。候補のartifact・image・DBを確認した後、manifestを一括で切り替えます。

```powershell
.\scripts\deploy-oss.ps1 -Ecosystem npm -AcceptOfficialDigestPolicy
```

`var/deploy/<実行ID>/deployment-receipt.json`に取得元・各ハッシュ・image IDが記録されます。以前のmanifestは同じフォルダの`scanners.before.yaml`へ保存し、古いDB世代も残します。

### 6.3 スキャンする

```powershell
.\bin\security-gate.exe verify-scanners --root . --type oss
.\scripts\scan-oss.ps1 -Target 'var/targets/nulab/backlog-mcp-server'
```

`--type oss`はOSSに必要な3製品とOPAだけを検証します。省略すると未配備のMCP ScannerとScorecardも含めて検証します。WindowsでもOPAはLinuxコンテナで実行します。

レポートは`var/reports/oss/<対象>/<実行日時>/`にJSON・HTML・Markdown・CSVで出力します。`scanner_runs`がすべて`COMPLETE`であればスキャナーが完了しています。`REVIEW`・`BLOCK`は検出内容による通常の判定で、`ERROR`は検査の失敗です。DBが古い場合もpolicyに従って`REVIEW`になります。

| エラー | 確認する箇所 |
| --- | --- |
| `SCANNER_INTEGRITY_FAILURE` | manifestの`runtime_path`とSHA-256 |
| `UNSUPPORTED_SECURITY_REQUIREMENT` | imageが未配備のzero digestのままか |
| `UNVERIFIED_SCANNER_IMAGE` | 同じDocker Linux engineに固定IDのimageがあるか |
| `DB_INTEGRITY_FAILURE` | `var/cache/<scanner>/<世代>/metadata.json`と記録された全ファイル |
| `OPA_POLICY_EVALUATION_FAILURE` | OPA image、policyの配置、Dockerの稼働状態 |

MCP Scanner・Scorecard・署名/provenanceについて残る条件は[未解決の要件](../BLOCKED_SECURITY_REQUIREMENTS.md)を参照してください。
