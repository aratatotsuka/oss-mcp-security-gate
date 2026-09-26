# 環境構築手順

この手順は、ソースからCLIをビルドして開発・ポリシーテストを実行するところまでと、実スキャンに必要な配備条件を扱います。コマンドはリポジトリのルートで実行してください。

## 1. 必要なツール

| 用途 | ツール | 確認コマンド |
| --- | --- | --- |
| ソース取得 | Git | `git --version` |
| ビルド・Goテスト | Go 1.24以上 | `go version` |
| 開発用Regoテスト・ポリシー評価 | OPA CLI 1.21.0 | `opa version` |
| Windowsの補助スクリプト | Windows PowerShell 5.1以上またはPowerShell 7 | `$PSVersionTable.PSVersion` |
| 実スキャン・隔離テスト | Docker CLIと稼働中のLinux engine | `docker info --format '{{.OSType}}'`（`linux`） |

GoとOPAは実行ファイルを`PATH`から呼べるようにします。Goのツールチェーンはリポジトリ外にインストールします。OPAはビルドだけなら不要ですが、Regoテスト、GoからのOPA連携テスト、実際のポリシー判定に必要です。Dockerは通常のGo/OPAテストとビルドには不要です。Windowsは開発・単体テスト用で、本番の隔離実行はhardening済みLinux workerを使用します。以下のコマンド例はWindows amd64 / Linux amd64向けです。他のCPUでは対応する公式配布物を選んでください。

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

`opa version`が`1.21.0`を表示することを確認します。次回以降のPowerShellでも使うには、Windowsの「環境変数」でユーザーの`Path`に`$HOME\Tools\OPA`の実際の絶対パスを追加し、新しいPowerShellを開きます。

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

ビルド直後の`config/scanners.yaml`には未配備を表すzero digestが入っています。scanner artifact、内部worker image、offline DBを用意していない状態で`scan`や`verify-scanners`が失敗するのは意図した動作です。開発テストのためにzero digestを架空のdigestに置き換えないでください。

配備責任者は、targetとは分離したUpdate workerで次を行います。

1. `scripts/update-security-data.ps1 -Scanner osv-scanner`などで取得計画を確認します。`-Execute`はquarantineへの取得とSHA-256検証までで、署名・provenance・advisoryの承認は完了しません。
2. 各scannerの署名、provenance、Security Advisoryを確認し、承認済みartifactをmanifestの`runtime_path`へ配置します。worker imageを内部のimmutable registryへ登録し、`worker_image`に実際の`image@sha256:...`を記録します。
3. OSV-ScannerとTrivyのoffline DB/check bundleを別pipelineで取得・検証し、`scripts/admit-security-data.ps1`で承認済みcacheへ入れます。scan workerには読み取り専用で渡します。
4. DockerのLinux engineから承認済みimage digestを参照できるようにし、`./bin/security-gate verify-scanners --root <Security Gateのルート>`を実行します。Windowsでは`./bin/security-gate.exe`を使います。

具体的な承認・隔離条件は[詳細設計](detailed-design.md)と[worker image admission](../workers/README.md)を参照してください。Cisco MCP ScannerのPython base/依存lock、ScorecardのGitHub宛て通信制御、Gitleaksのprovenanceには[未解決の要件](../BLOCKED_SECURITY_REQUIREMENTS.md)があります。これらの条件が満たされるまで、本番用workerの配備完了とは扱いません。

実scanner出力を使う任意のE2Eテストは[E2E fixtures](../tests/e2e/README.md)を参照してください。`SECURITY_GATE_REAL_E2E_DIR`が未設定なら、このテストはskipされます。
