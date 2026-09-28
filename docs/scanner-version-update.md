# 検証ツールの版を更新する

`scripts/update-scanner-versions.ps1` は、公式配布元の最新版を調べ、候補を取得し、承認または対応製品の自動検証後に manifest と実行用 artifact を更新します。対象は OSV-Scanner、Trivy、Gitleaks、Scorecard、MCP Scanner、OPA です。Docker 実行中の OPA は、新しい候補からローカル image を再構築します。他製品の image 構築・配備は別途必要です。

## 1. 候補を作る

リポジトリのルートで実行します。`-Scanner` を省くと manifest の全製品を調べます。

```powershell
.\scripts\update-scanner-versions.ps1 -Scanner opa
# 全製品を確認する場合
.\scripts\update-scanner-versions.ps1
```

最新版が現在の固定版と同じなら `CURRENT` を表示します。新しい版があれば公式 GitHub release または PyPI から現在と同じ Linux amd64 用の artifact を `var/update-candidates/<製品>/<版>/<実行ID>/` に取得します。GitHub release asset または PyPI が公表する SHA-256 と照合し、`candidate.json` と `approval.template.json` を保存して `PENDING_APPROVAL` を表示します。取得や照合に失敗した場合、配備中の manifest は変わりません。

## 2. 候補を検証して承認する

配備責任者は候補の署名、provenance、Security Advisory、CLI/出力形式の互換性を確認します。製品に応じて [GitHub artifact attestation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) または [PyPI attestation](https://docs.pypi.org/attestations/consuming-attestations/) を確認し、結果を保存します。`approval.template.json` を別名でコピーし、確認できた項目だけ `true` にし、確認方法、証跡、承認者を記入します。`candidate_sha256` と `artifact_sha256` は変更しません。

`advisory_checked_at` には、Advisory を確認した実際の日時をタイムゾーン付きで記入します（例：`2026-09-28T09:00:00+09:00`）。確認後に公開された情報を見落とさないよう、一覧取得の開始時刻を使います。空欄や未来の日時では反映できません。以前に生成した承認テンプレートにもこの項目を追加してください。

OPA 以外では、検証した artifact から worker image を作り、内部 registry に登録した実 digest を `worker_image` に記入します。`registry.example.invalid`、zero digest、tag だけの値は受け付けません。Docker 実行中の OPA はこの欄を使わず、承認された候補から script が image を構築し、版と Rego テストを確認して新しい image ID を反映します。Docker の Linux engine が必要です。OPA の `worker_image` が空欄の場合は Linux / PowerShell 7 上で反映してください。コピー先の実行権限、版、Rego テストを確認します。OSV/Trivy では offline DB との互換性、Scorecard では通信制御、MCP Scanner では Python 依存関係も確認します。未解決の [セキュリティ要件](../BLOCKED_SECURITY_REQUIREMENTS.md) がある場合は承認しません。

`signature_verified` などの真偽値は作業者の申告です。このスクリプトは署名や provenance 自体を暗号学的に検証せず、承認記録の内容と候補ファイルの SHA-256 を照合します。承認記録と証跡はレビュー可能な場所に保管してください。

## 3. 承認済み候補を反映する

```powershell
.\scripts\update-scanner-versions.ps1 -Mode Apply `
  -Candidate 'var/update-candidates/opa/1.21.0/<実行ID>/candidate.json' `
  -ApprovalRecord 'var/update-candidates/opa/1.21.0/<実行ID>/approval.json'
```

この操作は候補作成時から manifest が変わっていないこと、承認記録が候補と一致すること、取得済み artifact の SHA-256 が一致することを確認します。成功すると artifact を新しい `runtime_path` にコピーし、`config/scanners.yaml` の対象製品の版、URI、SHA-256、path、承認日、Advisory 確認日時を更新します。Docker 実行中の OPA は新しい image ID も同時に更新し、image 構築・版確認・テストの失敗時は manifest を切り替えません。古い版のファイルは残るため、問題があれば Git の manifest 差分を戻して切り戻せます。相対パスは PowerShell の現在のフォルダを基準に解決します。

反映後は `git diff -- config/scanners.yaml` で変更を確認し、Go/Rego テストと新しい scanner による実スキャンを行います。Linux worker で `verify-scanners` を実行し、`scanner_runs` が全て `COMPLETE` であることを確認してから配備してください。`MANIFEST_UPDATED` は配備完了やスキャン成功を意味しません。

`update-security-data.ps1` は既に manifest に固定された版の取得用です。最新版の候補作成にはこのページの `update-scanner-versions.ps1` を使います。

## 人間の承認なしで OPA を本番更新する

Linux の Update worker で [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux)、[GitHub CLI (`gh`)](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)、Go を用意し、次を実行します。新しい候補の取得から検証、`config/scanners.yaml` と Linux 用 OPA artifact の更新まで一度に行います。既存の `PENDING_APPROVAL` 候補を使う場合は `-Candidate` でその `candidate.json` を指定します。

```bash
pwsh ./scripts/update-scanner-versions.ps1 -Mode Auto -Scanner opa
# 既存候補を使う場合
pwsh ./scripts/update-scanner-versions.ps1 -Mode Auto -Candidate 'var/update-candidates/opa/1.21.0/<実行ID>/candidate.json'
```

自動更新は、候補の SHA-256、GitHub の暗号学的に署名された release asset attestation、前回の advisory 確認日時以降の新規・更新 repository advisory、候補 OPA 自身の版・Rego テスト、候補 OPA を使った Go テストを確認します。[`gh release verify-asset` の仕様](https://cli.github.com/manual/gh_release_verify-asset)に従い、release と artifact の対応を検証します。release attestation はビルド工程の詳細な provenance を証明するものではありません。検証結果は候補フォルダの `release-attestation.json` と `automatic-verification.json` に記録します。いずれかが失敗した場合、manifest は更新しません。

この経路は現在 **OPA のみ** 対応します。Docker 実行中の場合は候補から image を再構築し、新しい image でも版・Rego テストを確認します。Docker が利用できない場合は停止し、旧 image を残したまま更新成功とは扱いません。OSV-Scanner、Trivy、Gitleaks、Scorecard、MCP Scanner は worker image の構築・登録や製品別の provenance 検証などが未自動化のため、`-Mode Auto` では拒否します。`PENDING_APPROVAL` はそのまま残り、本番配備へ昇格しません。Windows 上では Linux 用 OPA を実行して互換性を確認できないため、`-Mode Auto` を拒否します。

Advisory の確認時刻は一覧取得の開始時点を `security_advisory_checked_at` に保存します。日付のみの既存 manifest はその日の UTC 00:00 として扱うため、同日中に公開・修正された Advisory があれば再確認が必要です。

`MANIFEST_UPDATED` はローカルの manifest と artifact の更新完了を示します。配備先への配布と実スキャンの確認は別途必要です。既存の `verify-scanners` は全製品の image/DB を確認するため、未配備の製品が残る環境では引き続き失敗します。
