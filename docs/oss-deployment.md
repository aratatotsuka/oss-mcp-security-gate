# OSS実スキャンの準備と実行

リポジトリのルートでPowerShellを開きます。Go、Docker CLI、DockerのLinux engineが必要です。WindowsでもLinuxコンテナで4製品を動かすため、PATH上のWindows版OPAは実スキャンに使いません。

## 1. 準備して確認する

```powershell
docker info --format '{{.OSType}}' # linux を確認
.\scripts\deploy-oss.ps1 -PrepareOnly -Ecosystem npm
```

`npm`はBacklog MCP ServerなどのJavaScript/TypeScript用です。Goなら`-Ecosystem Go`、Pythonなら`-Ecosystem PyPI`、複数なら`-Ecosystem Go,npm,PyPI`を指定します。省略時はGoだけです。JavaのJARも調べる場合は`-Ecosystem Maven -IncludeJavaDB`を指定してください。対応するOSV DBがない対象の検査は失敗します。ecosystem名は[OSV公式一覧](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)を参照してください。

このスクリプトは、次を一括で行います。

1. manifestの固定版について、公式GitHub releaseのURL・asset digestとローカルSHA-256を照合する。取得済みのquarantineがあれば再利用する。
2. 前回の確認日時以降に公開・修正されたSecurity Advisoryがあれば停止する。日付だけの既存記録は UTC の当日開始時刻として扱う。
3. アーカイブを制限付きで展開し、OSV・Trivy・Gitleaks・OPAの最小Docker imageを作る。対象リポジトリからはビルドしない。
4. 各製品の版とOPAのポリシーテストを確認する。
5. OSVの指定ecosystemのDB、Trivyの脆弱性DBとchecksを取得する。取得用コンテナには検査対象を渡さない。
6. DB一式の各ファイルをSHA-256で記録し、読み取り専用で使う世代フォルダへ配置する。
7. artifact・image ID・DBを検証し、配備記録を残す。

`-PrepareOnly`では、通常の`config/scanners.yaml`を変更せず、`var/deploy/<実行ID>/prepared-root`に別の実行環境を作ります。imageはローカルDocker engineに追加されます。取得にはネットワークと十分なディスク容量が必要です。

Advisory の一覧取得を始めた時刻を `security_advisory_checked_at` に記録します。image・DB の準備中に公開された Advisory は、次回の配備時に確認対象になります。

### 検証方式の範囲

このスクリプトの方式は **公式HTTPS配布元のdigest照合** です。署名・SLSA build provenance・DBのpublisher署名を検証したとは扱いません。GitHub releaseや配布元自体が侵害された場合の真正性を保証できません。配備記録とmanifestにもこの範囲を明記します。

署名・provenance検証を必須とする組織では、この方式だけで本番に反映しないでください。[従来のworker admission手順](../workers/README.md)と[未解決要件](../BLOCKED_SECURITY_REQUIREMENTS.md)に従って追加検証します。

## 2. 通常のスキャン設定へ反映する

上の検証方式を採用する場合に実行します。

```powershell
.\scripts\deploy-oss.ps1 -Ecosystem npm -AcceptOfficialDigestPolicy
```

候補のartifact・image・DBの検証が成功した後、`config/scanners.yaml`を一括で切り替えます。古いDB世代は保持し、切り替え前のmanifestは`var/deploy/<実行ID>/scanners.before.yaml`へ保存します。途中で失敗した場合、切り替え前のmanifestは維持します。

`update-security-data.ps1 -Execute`のループを実行済みでも、このコマンドが必要です。取得だけではimage、DB、OPAの実行経路は用意されません。配備スクリプトは取得済みartifactを再利用できるため、ループの再実行は不要です。版の更新は別の[更新手順](scanner-version-update.md)です。

## 3. スキャンする

```powershell
.\bin\security-gate.exe verify-scanners --root . --type oss
.\scripts\scan-oss.ps1 -Target 'var/targets/nulab/backlog-mcp-server'
```

レポートは`var/reports/oss/<対象>/<実行日時>/`にJSON・HTML・Markdown・CSVで出ます。3つの`scanner_runs`がすべて`COMPLETE`であることを確認してください。`REVIEW`・`BLOCK`は検出内容による通常の判定、`ERROR`は検査やOPAの失敗です。終了コードは`0=ALLOW / 2=REVIEW / 3=BLOCK / 4=ERROR`です。

準備用の環境だけで確認する場合は、表示された実行IDに置き換えます。

```powershell
New-Item -ItemType Directory -Force 'var/reports/oss/prepared-check' | Out-Null
.\bin\security-gate.exe scan `
  --root 'var/deploy/<実行ID>/prepared-root' `
  --target 'var/targets/nulab/backlog-mcp-server' --type oss `
  --output 'var/reports/oss/prepared-check/report.json'
```

## 4. 定期的にDBを更新する

同じ配備コマンドを再実行すると、新しいDB世代を用意してから切り替えます。スキャン中はネットワークなし、対象・DB・設定は読み取り専用、非rootで動かします。OSV 2.6.0の実装が参照する`osv-scalibr/<ecosystem>/all.zip`へ配置し、Trivyの解析用cacheはメモリ内に置きます。

DBを再取得しない場合だけ`-SkipDataUpdate`を指定できます。既存の世代が検証できなければ停止します。DBが古い場合はpolicyに従って`REVIEW`になります。`-PrepareOnly`との併用はできません。

ローカルimage IDはそのDocker engine固有の配備です。別の端末へmanifestだけコピーしても動きません。その端末でも配備するか、同じimageをsave/loadしてIDを検証してください。従来のregistry `image@sha256:...`指定にも対応しています。

MCP静的検査とScorecardの配備はこのスクリプトの対象外です。Goでのoffline実スキャンは検証済みですが、各ecosystemのlockfile、Java DB、CIでの動作は導入先でも確認してください。
