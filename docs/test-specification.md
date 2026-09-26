# テスト仕様書

## 対象

- 対象機能：スキャナ出力正規化、判定、整合性検証、隔離、機密値マスク、レポート、監査、および横断検証
- 実装ファイル：`internal/**`、`policies/main.rego`、`cmd/security-gate/main.go`
- テストファイル：`internal/**/*_test.go`、`policies/tests/main_test.rego`、`tests/*_test.go`、`tests/runtime-isolation.*`
- テストフレームワーク：Go 標準 `testing`、OPA `opa test`、PowerShell / shell の実行スクリプト。外部 Go テストライブラリなし。
- テストデータ：テスト内 JSON 文字列、`t.TempDir()` 内のファイル、`tests/e2e/fixtures`、任意の実スキャナ出力。mock / stub / spy は使用していない。
- setup / teardown：各 Go テストで局所生成し、`t.TempDir()` が自動削除する。隔離スクリプトは一時ディレクトリを `finally` / `trap` で削除する。共通ヘルパーは `baseInput`、`ctx`、`mustJSON`。
- 外部依存：任意の OPA CLI、Docker 実行環境、実スキャナ JSON。DB はアプリケーション DB ではなくファイル形式の脆弱性 DB キャッシュ。ファイルは監査ログ・レポート・スキャナ実体・DB。環境変数は `OPA_TEST_BIN`、`SECURITY_GATE_REAL_E2E_DIR`、`SECURITY_GATE_TEST_IMAGE`。

## 対象機能ごとの概要

| 機能 | 責務と対象 | 既存テストの主眼 |
| --- | --- | --- |
| 正規化 | `internal/normalize` が5種の外部出力を Finding に変換 | 典型入力、欠損形式、秘密情報マスク |
| 判定 | `internal/policy` と `policies/main.rego` が決定を返す | ALLOW/REVIEW/BLOCK/ERROR と例外・鮮度 |
| 信頼境界 | `manifest`、`scanners`、`integrity`、`sandbox`、`runner`、`secret` | 承認設定、scanner 選択、digest、隔離引数、実行制限、マスク |
| 永続化 | `report`、`audit` | 秘密情報、symlink、監査連鎖 |
| 横断 | `tests` と隔離スクリプト | 引数契約、任意の実データとコンテナ実行 |

## テストケース一覧

以下の各表の「前提・入力」「実行・期待」が Given / When / Then を表す。特記がなければ mock / stub / spy は使用せず、実装関数を直接呼ぶ。

### 正規化

#### TC-001: OSV の CVSS 数値と修正版

| 項目 | 内容 |
| --- | --- |
| What | OSV の 正常系。入力から得る結果・状態を検証。入力：OSV 脆弱性1件、CVSS 9.8、fixed 1.1。確認：CRITICAL と修正版 1.1、件数1 |
| Why | 脆弱性の重要度と修正版を失わず報告するため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | OSV 脆弱性1件、CVSS 9.8、fixed 1.1 の条件で実行 |
| Where | `internal/normalize/normalize.go:OSV` |
| How | Arrange: OSV 脆弱性1件、CVSS 9.8、fixed 1.1 → Act: `OSV` を呼ぶ → Assert: CRITICAL と修正版 1.1、件数1 |
| 前提条件・入力 | OSV 脆弱性1件、CVSS 9.8、fixed 1.1 |
| 実行内容・期待結果 | CRITICAL と修正版 1.1、件数1 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestOSV` |

#### TC-002: OSV の database_specific 重要度

| 項目 | 内容 |
| --- | --- |
| What | OSV の 回帰。入力から得る結果・状態を検証。入力：CVSS ベクター文字列と database_specific HIGH。確認：HIGH、件数1 |
| Why | 実データ形状のベクター文字列で UNKNOWN へ落ちる回帰を防ぐため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | CVSS ベクター文字列と database_specific HIGH の条件で実行 |
| Where | `internal/normalize/normalize.go:OSV` |
| How | Arrange: CVSS ベクター文字列と database_specific HIGH → Act: `OSV` を呼ぶ → Assert: HIGH、件数1 |
| 前提条件・入力 | CVSS ベクター文字列と database_specific HIGH |
| 実行内容・期待結果 | HIGH、件数1 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestOSVSeverityFromDatabaseSpecific` |

#### TC-003: Trivy の3カテゴリ変換

| 項目 | 内容 |
| --- | --- |
| What | Trivy の 正常系。入力から得る結果・状態を検証。入力：脆弱性・設定不備・secret を各1件。確認：結果3件 |
| Why | 3種の検出を Finding に取り込むため。ただし各カテゴリの値は未検証 |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 脆弱性・設定不備・secret を各1件 の条件で実行 |
| Where | `internal/normalize/normalize.go:Trivy` |
| How | Arrange: 脆弱性・設定不備・secret を各1件 → Act: `Trivy` を呼ぶ → Assert: 結果3件 |
| 前提条件・入力 | 脆弱性・設定不備・secret を各1件 |
| 実行内容・期待結果 | 結果3件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestTrivy` |

#### TC-004: Trivy の secret 非漏えい

| 項目 | 内容 |
| --- | --- |
| What | Trivy の セキュリティ。入力から得る結果・状態を検証。入力：Match に AWS 形式の資格情報。確認：シリアライズ後に原文がない |
| Why | 検出値をレポートへ漏らさないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | Match に AWS 形式の資格情報 の条件で実行 |
| Where | `internal/normalize/normalize.go:Trivy` |
| How | Arrange: Match に AWS 形式の資格情報 → Act: `Trivy` を呼ぶ → Assert: シリアライズ後に原文がない |
| 前提条件・入力 | Match に AWS 形式の資格情報 |
| 実行内容・期待結果 | シリアライズ後に原文がない |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestTrivy` |

#### TC-005: Gitleaks の secret 非漏えい

| 項目 | 内容 |
| --- | --- |
| What | Gitleaks の セキュリティ。入力から得る結果・状態を検証。入力：Secret に ghp 形式の資格情報。確認：結果1件、シリアライズ後に原文がない |
| Why | 資格情報漏えいを防ぐため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | Secret に ghp 形式の資格情報 の条件で実行 |
| Where | `internal/normalize/normalize.go:Gitleaks` |
| How | Arrange: Secret に ghp 形式の資格情報 → Act: `Gitleaks` を呼ぶ → Assert: 結果1件、シリアライズ後に原文がない |
| 前提条件・入力 | Secret に ghp 形式の資格情報 |
| 実行内容・期待結果 | 結果1件、シリアライズ後に原文がない |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestGitleaks` |

#### TC-006: Scorecard の低スコア検出

| 項目 | 内容 |
| --- | --- |
| What | Scorecard の 境界値。入力から得る結果・状態を検証。入力：スコア2と9、既定閾値7。確認：1件、HIGH |
| Why | 低スコアのみレビュー対象へ変換するため。ただしスコア9除外の理由は件数からの間接確認 |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | スコア2と9、既定閾値7 の条件で実行 |
| Where | `internal/normalize/normalize.go:Scorecard` |
| How | Arrange: スコア2と9、既定閾値7 → Act: `Scorecard` を呼ぶ → Assert: 1件、HIGH |
| 前提条件・入力 | スコア2と9、既定閾値7 |
| 実行内容・期待結果 | 1件、HIGH |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestScorecard` |

#### TC-007: MCP の UNSAFE 検出

| 項目 | 内容 |
| --- | --- |
| What | MCP の 正常系。入力から得る結果・状態を検証。入力：UNSAFE・YARA の finding 1件。確認：結果1件 |
| Why | 危険な MCP メタデータを捨てないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | UNSAFE・YARA の finding 1件 の条件で実行 |
| Where | `internal/normalize/normalize.go:MCP` |
| How | Arrange: UNSAFE・YARA の finding 1件 → Act: `MCP` を呼ぶ → Assert: 結果1件 |
| 前提条件・入力 | UNSAFE・YARA の finding 1件 |
| 実行内容・期待結果 | 結果1件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMCP` |

#### TC-008: 不正 JSON の拒否

| 項目 | 内容 |
| --- | --- |
| What | Parse の 入力バリデーション。入力から得る結果・状態を検証。入力：trivy 入力が { のみ。確認：error 非 nil |
| Why | 構文が壊れたスキャナ出力を成功扱いしないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | trivy 入力が { のみ の条件で実行 |
| Where | `internal/normalize/normalize.go:Parse` |
| How | Arrange: trivy 入力が { のみ → Act: `Parse` を呼ぶ → Assert: error 非 nil |
| 前提条件・入力 | trivy 入力が { のみ |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMalformed` |

#### TC-009: OSV 必須 results 欠落

| 項目 | 内容 |
| --- | --- |
| What | OSV の 入力バリデーション。入力から得る結果・状態を検証。入力：osv-scanner 入力 {}。確認：error 非 nil |
| Why | 必須構造欠落を空の安全な結果と誤認しないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | osv-scanner 入力 {} の条件で実行 |
| Where | `internal/normalize/normalize.go:OSV` |
| How | Arrange: osv-scanner 入力 {} → Act: `OSV` を呼ぶ → Assert: error 非 nil |
| 前提条件・入力 | osv-scanner 入力 {} |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMalformed` |

#### TC-010: Trivy 必須 Results 欠落

| 項目 | 内容 |
| --- | --- |
| What | Trivy の 入力バリデーション。入力から得る結果・状態を検証。入力：trivy 入力 {}。確認：error 非 nil |
| Why | 必須構造欠落を空の安全な結果と誤認しないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | trivy 入力 {} の条件で実行 |
| Where | `internal/normalize/normalize.go:Trivy` |
| How | Arrange: trivy 入力 {} → Act: `Trivy` を呼ぶ → Assert: error 非 nil |
| 前提条件・入力 | trivy 入力 {} |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMalformed` |

#### TC-011: Gitleaks null の拒否

| 項目 | 内容 |
| --- | --- |
| What | Gitleaks の 入力バリデーション。入力から得る結果・状態を検証。入力：gitleaks 入力 null。確認：error 非 nil |
| Why | 配列欠落を検出0件と誤認しないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | gitleaks 入力 null の条件で実行 |
| Where | `internal/normalize/normalize.go:Gitleaks` |
| How | Arrange: gitleaks 入力 null → Act: `Gitleaks` を呼ぶ → Assert: error 非 nil |
| 前提条件・入力 | gitleaks 入力 null |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMalformed` |

#### TC-012: Scorecard 必須項目欠落

| 項目 | 内容 |
| --- | --- |
| What | Scorecard の 入力バリデーション。入力から得る結果・状態を検証。入力：scorecard 入力 {}。確認：error 非 nil |
| Why | score/checks 欠落を成功扱いしないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | scorecard 入力 {} の条件で実行 |
| Where | `internal/normalize/normalize.go:Scorecard` |
| How | Arrange: scorecard 入力 {} → Act: `Scorecard` を呼ぶ → Assert: error 非 nil |
| 前提条件・入力 | scorecard 入力 {} |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMalformed` |

#### TC-013: MCP 空オブジェクト拒否

| 項目 | 内容 |
| --- | --- |
| What | MCP の 入力バリデーション。入力から得る結果・状態を検証。入力：mcp-scanner 入力 {}。確認：error 非 nil |
| Why | 空の不正出力を成功扱いしないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | mcp-scanner 入力 {} の条件で実行 |
| Where | `internal/normalize/normalize.go:MCP` |
| How | Arrange: mcp-scanner 入力 {} → Act: `MCP` を呼ぶ → Assert: error 非 nil |
| 前提条件・入力 | mcp-scanner 入力 {} |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestMalformed` |

#### TC-014: 重要度 critical の変換

| 項目 | 内容 |
| --- | --- |
| What | Severity の 正常系。入力から得る結果・状態を検証。入力：critical。確認：CRITICAL |
| Why | 大文字小文字が異なる重要度を正規化するため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | critical の条件で実行 |
| Where | `internal/normalize/normalize.go:Severity` |
| How | Arrange: critical → Act: `Severity` を呼ぶ → Assert: CRITICAL |
| 前提条件・入力 | critical |
| 実行内容・期待結果 | CRITICAL |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestSeverityMapping` |

#### TC-015: 重要度 moderate の変換

| 項目 | 内容 |
| --- | --- |
| What | Severity の 正常系。入力から得る結果・状態を検証。入力：moderate。確認：MEDIUM |
| Why | 別表記を共通重要度へ変換するため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | moderate の条件で実行 |
| Where | `internal/normalize/normalize.go:Severity` |
| How | Arrange: moderate → Act: `Severity` を呼ぶ → Assert: MEDIUM |
| 前提条件・入力 | moderate |
| 実行内容・期待結果 | MEDIUM |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestSeverityMapping` |

#### TC-016: 未知の重要度の変換

| 項目 | 内容 |
| --- | --- |
| What | Severity の 異常系。入力から得る結果・状態を検証。入力：n/a。確認：UNKNOWN |
| Why | 未知表記を既知の重要度と誤認しないため |
| Who | normalize の 正規化責務。呼び出し元との境界は戻り値・出力ファイル |
| When | n/a の条件で実行 |
| Where | `internal/normalize/normalize.go:Severity` |
| How | Arrange: n/a → Act: `Severity` を呼ぶ → Assert: UNKNOWN |
| 前提条件・入力 | n/a |
| 実行内容・期待結果 | UNKNOWN |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestSeverityMapping` |

### ネイティブ判定

#### TC-017: 完了・検出なしで ALLOW

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 正常系。入力から得る結果・状態を検証。入力：COMPLETE、検出なし、アドバイザリ確認済み。確認：ALLOW |
| Why | 安全条件を満たす入力を許可できるため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | COMPLETE、検出なし、アドバイザリ確認済み の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: COMPLETE、検出なし、アドバイザリ確認済み → Act: `Evaluate` を呼ぶ → Assert: ALLOW |
| 前提条件・入力 | COMPLETE、検出なし、アドバイザリ確認済み |
| 実行内容・期待結果 | ALLOW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestAllowOnlyCompleteClean` |

#### TC-018: FAILED は ALLOW にしない

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 異常系。入力から得る結果・状態を検証。入力：スキャナ状態 FAILED。確認：ALLOW 以外。ERROR の厳密値は既存テスト未保証 |
| Why | 失敗した検査を安全と判断しないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | スキャナ状態 FAILED の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: スキャナ状態 FAILED → Act: `Evaluate` を呼ぶ → Assert: ALLOW 以外。ERROR の厳密値は既存テスト未保証 |
| 前提条件・入力 | スキャナ状態 FAILED |
| 実行内容・期待結果 | ALLOW 以外。ERROR の厳密値は既存テスト未保証 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestFailuresNeverAllow` |

#### TC-019: TIMEOUT は ALLOW にしない

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 異常系。入力から得る結果・状態を検証。入力：スキャナ状態 TIMEOUT。確認：ALLOW 以外。ERROR の厳密値は既存テスト未保証 |
| Why | 時間切れの検査を安全と判断しないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | スキャナ状態 TIMEOUT の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: スキャナ状態 TIMEOUT → Act: `Evaluate` を呼ぶ → Assert: ALLOW 以外。ERROR の厳密値は既存テスト未保証 |
| 前提条件・入力 | スキャナ状態 TIMEOUT |
| 実行内容・期待結果 | ALLOW 以外。ERROR の厳密値は既存テスト未保証 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestFailuresNeverAllow` |

#### TC-020: PARTIAL は ALLOW にしない

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 異常系。入力から得る結果・状態を検証。入力：スキャナ状態 PARTIAL。確認：ALLOW 以外。REVIEW の厳密値は既存テスト未保証 |
| Why | 部分検査を安全と判断しないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | スキャナ状態 PARTIAL の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: スキャナ状態 PARTIAL → Act: `Evaluate` を呼ぶ → Assert: ALLOW 以外。REVIEW の厳密値は既存テスト未保証 |
| 前提条件・入力 | スキャナ状態 PARTIAL |
| 実行内容・期待結果 | ALLOW 以外。REVIEW の厳密値は既存テスト未保証 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestFailuresNeverAllow` |

#### TC-021: UNSUPPORTED は ALLOW にしない

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 異常系。入力から得る結果・状態を検証。入力：スキャナ状態 UNSUPPORTED。確認：ALLOW 以外。REVIEW の厳密値は既存テスト未保証 |
| Why | 未対応検査を安全と判断しないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | スキャナ状態 UNSUPPORTED の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: スキャナ状態 UNSUPPORTED → Act: `Evaluate` を呼ぶ → Assert: ALLOW 以外。REVIEW の厳密値は既存テスト未保証 |
| 前提条件・入力 | スキャナ状態 UNSUPPORTED |
| 実行内容・期待結果 | ALLOW 以外。REVIEW の厳密値は既存テスト未保証 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestFailuresNeverAllow` |

#### TC-022: 高信頼 secret は BLOCK

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の セキュリティ。入力から得る結果・状態を検証。入力：カテゴリ secret、信頼度 HIGH。確認：BLOCK |
| Why | 確認済み秘密情報を公開可能としないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | カテゴリ secret、信頼度 HIGH の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: カテゴリ secret、信頼度 HIGH → Act: `Evaluate` を呼ぶ → Assert: BLOCK |
| 前提条件・入力 | カテゴリ secret、信頼度 HIGH |
| 実行内容・期待結果 | BLOCK |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestBlockSecret` |

#### TC-023: 有効な例外は高重要度脆弱性を免除

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 状態遷移。入力から得る結果・状態を検証。入力：CVE-1 に対象 t・1時間後までの例外。確認：ALLOW |
| Why | 有効な承認例外を判定へ反映するため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | CVE-1 に対象 t・1時間後までの例外 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: CVE-1 に対象 t・1時間後までの例外 → Act: `Evaluate` を呼ぶ → Assert: ALLOW |
| 前提条件・入力 | CVE-1 に対象 t・1時間後までの例外 |
| 実行内容・期待結果 | ALLOW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionExpiry` |

#### TC-024: 失効した例外は免除しない

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 状態遷移。入力から得る結果・状態を検証。入力：同じ例外の期限を1秒前に変更。確認：REVIEW |
| Why | 期限切れ例外による見逃しを防ぐため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 同じ例外の期限を1秒前に変更 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: 同じ例外の期限を1秒前に変更 → Act: `Evaluate` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | 同じ例外の期限を1秒前に変更 |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionExpiry` |

#### TC-025: 72時間超の DB は REVIEW

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 境界値。入力から得る結果・状態を検証。入力：DB 更新が73時間前。確認：REVIEW |
| Why | 古い DB による見落としを許可しないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | DB 更新が73時間前 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: DB 更新が73時間前 → Act: `Evaluate` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | DB 更新が73時間前 |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestStaleDBReview` |

#### TC-026: 部分的 finding は REVIEW

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 異常系。入力から得る結果・状態を検証。入力：finding の ScanStatus PARTIAL。確認：REVIEW |
| Why | 結果が不完全な検出を安全と扱わないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | finding の ScanStatus PARTIAL の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: finding の ScanStatus PARTIAL → Act: `Evaluate` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | finding の ScanStatus PARTIAL |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestIncompleteFindingReview` |

#### TC-027: 設定した DB 期限を適用

| 項目 | 内容 |
| --- | --- |
| What | Evaluate の 境界値。入力から得る結果・状態を検証。入力：最大1時間、更新2時間前。確認：REVIEW |
| Why | 既定値で設定値を上書きしないため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 最大1時間、更新2時間前 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: 最大1時間、更新2時間前 → Act: `Evaluate` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | 最大1時間、更新2時間前 |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestConfiguredDBAge` |

#### TC-028: OPA CLI の正常応答を解析

| 項目 | 内容 |
| --- | --- |
| What | EvaluateOPA の 外部依存。入力から得る結果・状態を検証。入力：OPA_TEST_BIN 指定、完全かつ検出なし。確認：error なし、ALLOW。未指定なら skip |
| Why | Go と OPA CLI の最低限の接続を保証するため |
| Who | policy の ネイティブ判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | OPA_TEST_BIN 指定、完全かつ検出なし の条件で実行 |
| Where | `internal/policy/policy.go:EvaluateOPA` |
| How | Arrange: OPA_TEST_BIN 指定、完全かつ検出なし → Act: `EvaluateOPA` を呼ぶ → Assert: error なし、ALLOW。未指定なら skip |
| 前提条件・入力 | OPA_TEST_BIN 指定、完全かつ検出なし |
| 実行内容・期待結果 | error なし、ALLOW。未指定なら skip |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestEvaluateOPAIntegration` |

### OPA 判定

#### TC-029: 正常な入力は ALLOW・理由なし

| 項目 | 内容 |
| --- | --- |
| What | result の 正常系。入力から得る結果・状態を検証。入力：COMPLETE、検出なし。確認：ALLOW、理由空 |
| Why | OPA 判定の正常な基準を保証するため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | COMPLETE、検出なし の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: COMPLETE、検出なし → Act: `result` を呼ぶ → Assert: ALLOW、理由空 |
| 前提条件・入力 | COMPLETE、検出なし |
| 実行内容・期待結果 | ALLOW、理由空 |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_allow_clean_complete` |

#### TC-030: FAILED は ERROR

| 項目 | 内容 |
| --- | --- |
| What | result の 異常系。入力から得る結果・状態を検証。入力：FAILED の scanner_run。確認：ERROR |
| Why | 検査失敗を許可しないため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | FAILED の scanner_run の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: FAILED の scanner_run → Act: `result` を呼ぶ → Assert: ERROR |
| 前提条件・入力 | FAILED の scanner_run |
| 実行内容・期待結果 | ERROR |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_error_on_failure` |

#### TC-031: 高信頼 secret は BLOCK

| 項目 | 内容 |
| --- | --- |
| What | result の セキュリティ。入力から得る結果・状態を検証。入力：HIGH 信頼度 secret。確認：BLOCK |
| Why | 秘密情報の露出を遮断するため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | HIGH 信頼度 secret の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: HIGH 信頼度 secret → Act: `result` を呼ぶ → Assert: BLOCK |
| 前提条件・入力 | HIGH 信頼度 secret |
| 実行内容・期待結果 | BLOCK |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_block_secret` |

#### TC-032: HIGH 脆弱性は REVIEW

| 項目 | 内容 |
| --- | --- |
| What | result の 正常系。入力から得る結果・状態を検証。入力：HIGH 脆弱性。確認：REVIEW |
| Why | 高重要度脆弱性に人手判定を要求するため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | HIGH 脆弱性 の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: HIGH 脆弱性 → Act: `result` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | HIGH 脆弱性 |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_review_high_cve` |

#### TC-033: 古い DB は REVIEW

| 項目 | 内容 |
| --- | --- |
| What | result の 境界値。入力から得る結果・状態を検証。入力：DB 更新4日前。確認：REVIEW |
| Why | 古いデータのまま許可しないため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | DB 更新4日前 の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: DB 更新4日前 → Act: `result` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | DB 更新4日前 |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_review_stale_db` |

#### TC-034: アドバイザリ日時欠落は REVIEW

| 項目 | 内容 |
| --- | --- |
| What | result の 異常系。入力から得る結果・状態を検証。入力：COMPLETE だが advisory_checked_at なし。確認：REVIEW |
| Why | 更新確認不能の検査を許可しないため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | COMPLETE だが advisory_checked_at なし の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: COMPLETE だが advisory_checked_at なし → Act: `result` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | COMPLETE だが advisory_checked_at なし |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_review_missing_advisory` |

#### TC-035: 有効な例外は脆弱性を免除

| 項目 | 内容 |
| --- | --- |
| What | result の 状態遷移。入力から得る結果・状態を検証。入力：対象 t・期限翌日の CVE-1 例外。確認：ALLOW |
| Why | 例外を適用可能な finding に反映するため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 対象 t・期限翌日の CVE-1 例外 の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: 対象 t・期限翌日の CVE-1 例外 → Act: `result` を呼ぶ → Assert: ALLOW |
| 前提条件・入力 | 対象 t・期限翌日の CVE-1 例外 |
| 実行内容・期待結果 | ALLOW |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_active_exception_suppresses_review` |

#### TC-036: 部分 finding は REVIEW

| 項目 | 内容 |
| --- | --- |
| What | result の 異常系。入力から得る結果・状態を検証。入力：LOW だが PARTIAL。確認：REVIEW |
| Why | 重要度が低くても不完全な結果を許可しないため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | LOW だが PARTIAL の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: LOW だが PARTIAL → Act: `result` を呼ぶ → Assert: REVIEW |
| 前提条件・入力 | LOW だが PARTIAL |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_partial_finding_requires_review` |

#### TC-037: 重大な設定不備に有効例外を適用

| 項目 | 内容 |
| --- | --- |
| What | result の 状態遷移。入力から得る結果・状態を検証。入力：CRITICAL 設定不備と有効例外。確認：ALLOW |
| Why | 実装上、設定不備は例外対象であることを保証するため |
| Who | Rego の OPA 判定責務。呼び出し元との境界は戻り値・出力ファイル |
| When | CRITICAL 設定不備と有効例外 の条件で実行 |
| Where | `policies/main.rego:result` |
| How | Arrange: CRITICAL 設定不備と有効例外 → Act: `result` を呼ぶ → Assert: ALLOW |
| 前提条件・入力 | CRITICAL 設定不備と有効例外 |
| 実行内容・期待結果 | ALLOW |
| Mock / Stub / Fixture | Rego の base 入力 |
| 対応テストコード | `policies/tests/main_test.rego:test_active_exception_suppresses_critical_misconfiguration` |

### 監査・整合性

#### TC-038: 追記監査ログのハッシュ連鎖

| 項目 | 内容 |
| --- | --- |
| What | Append の ファイル。入力から得る結果・状態を検証。入力：一時 JSONL に2件追記。確認：2行、先頭 hash 非空、2行目 previous_hash が先頭 hash |
| Why | 連続記録の参照関係を保つため。ただし改ざん検出は検証していない |
| Who | audit の 監査・整合性責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 一時 JSONL に2件追記 の条件で実行 |
| Where | `internal/audit/audit.go:Append` |
| How | Arrange: 一時 JSONL に2件追記 → Act: `Append` を呼ぶ → Assert: 2行、先頭 hash 非空、2行目 previous_hash が先頭 hash |
| 前提条件・入力 | 一時 JSONL に2件追記 |
| 実行内容・期待結果 | 2行、先頭 hash 非空、2行目 previous_hash が先頭 hash |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル |
| 対応テストコード | `internal/audit/audit_test.go:TestAppendHashChain` |

### スキャナ整合性

#### TC-039: ハッシュ不一致は拒否

| 項目 | 内容 |
| --- | --- |
| What | Verify の 異常系。入力から得る結果・状態を検証。入力：一時ファイル内容 hostile、期待 hash は0を64文字。確認：OK=false、HASH_MISMATCH を含む error |
| Why | 未承認のスキャナ実体を使用しないため |
| Who | integrity の スキャナ整合性責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 一時ファイル内容 hostile、期待 hash は0を64文字 の条件で実行 |
| Where | `internal/integrity/integrity.go:Verify` |
| How | Arrange: 一時ファイル内容 hostile、期待 hash は0を64文字 → Act: `Verify` を呼ぶ → Assert: OK=false、HASH_MISMATCH を含む error |
| 前提条件・入力 | 一時ファイル内容 hostile、期待 hash は0を64文字 |
| 実行内容・期待結果 | OK=false、HASH_MISMATCH を含む error |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル |
| 対応テストコード | `internal/integrity/integrity_test.go:TestHashMismatch` |

### レポート

#### TC-040: レポート内秘密情報をマスク

| 項目 | 内容 |
| --- | --- |
| What | Write の セキュリティ。入力から得る結果・状態を検証。入力：finding と例外に資格情報と secret 証跡。確認：保存ファイルに原文なし、ResultHash に sha256 接頭辞 |
| Why | レポート出力で機密情報を漏らさないため |
| Who | report の レポート責務。呼び出し元との境界は戻り値・出力ファイル |
| When | finding と例外に資格情報と secret 証跡 の条件で実行 |
| Where | `internal/report/report.go:Write` |
| How | Arrange: finding と例外に資格情報と secret 証跡 → Act: `Write` を呼ぶ → Assert: 保存ファイルに原文なし、ResultHash に sha256 接頭辞 |
| 前提条件・入力 | finding と例外に資格情報と secret 証跡 |
| 実行内容・期待結果 | 保存ファイルに原文なし、ResultHash に sha256 接頭辞 |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル |
| 対応テストコード | `internal/report/report_test.go:TestWriteMasksSecret` |

#### TC-041: シンボリックリンク出力先を拒否

| 項目 | 内容 |
| --- | --- |
| What | Write の ファイル・異常系。入力から得る結果・状態を検証。入力：出力先が既存ファイルへの symlink。確認：error、リンク先の内容不変。symlink 作成不能なら skip |
| Why | 意図しないファイル上書きを防ぐため |
| Who | report の レポート責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 出力先が既存ファイルへの symlink の条件で実行 |
| Where | `internal/report/report.go:Write` |
| How | Arrange: 出力先が既存ファイルへの symlink → Act: `Write` を呼ぶ → Assert: error、リンク先の内容不変。symlink 作成不能なら skip |
| 前提条件・入力 | 出力先が既存ファイルへの symlink |
| 実行内容・期待結果 | error、リンク先の内容不変。symlink 作成不能なら skip |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル |
| 対応テストコード | `internal/report/report_test.go:TestWriteRejectsSymlinkDestination` |

### コマンド実行

#### TC-042: 実行タイムアウト

| 項目 | 内容 |
| --- | --- |
| What | Run の 異常系。入力から得る結果・状態を検証。入力：2秒 sleep、制限50ms。確認：TimedOut=true |
| Why | スキャナ停止時に無期限で待たないため |
| Who | runner の コマンド実行責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 2秒 sleep、制限50ms の条件で実行 |
| Where | `internal/runner/runner.go:Run` |
| How | Arrange: 2秒 sleep、制限50ms → Act: `Run` を呼ぶ → Assert: TimedOut=true |
| 前提条件・入力 | 2秒 sleep、制限50ms |
| 実行内容・期待結果 | TimedOut=true |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/runner/runner_test.go:TestTimeout` |

#### TC-043: 存在しないコマンド

| 項目 | 内容 |
| --- | --- |
| What | Run の 異常系。入力から得る結果・状態を検証。入力：存在しない実行ファイル。確認：Err 非 nil |
| Why | 起動不能を成功扱いしないため |
| Who | runner の コマンド実行責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 存在しない実行ファイル の条件で実行 |
| Where | `internal/runner/runner.go:Run` |
| How | Arrange: 存在しない実行ファイル → Act: `Run` を呼ぶ → Assert: Err 非 nil |
| 前提条件・入力 | 存在しない実行ファイル |
| 実行内容・期待結果 | Err 非 nil |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/runner/runner_test.go:TestMalformedCommandFails` |

#### TC-044: 標準出力制限

| 項目 | 内容 |
| --- | --- |
| What | Run の 境界値。入力から得る結果・状態を検証。入力：4096 byte 出力、上限128。確認：Err 非 nil、Output 長128 |
| Why | 大量出力による資源消費を抑えるため |
| Who | runner の コマンド実行責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 4096 byte 出力、上限128 の条件で実行 |
| Where | `internal/runner/runner.go:Run` |
| How | Arrange: 4096 byte 出力、上限128 → Act: `Run` を呼ぶ → Assert: Err 非 nil、Output 長128 |
| 前提条件・入力 | 4096 byte 出力、上限128 |
| 実行内容・期待結果 | Err 非 nil、Output 長128 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/runner/runner_test.go:TestOutputLimit` |

### Docker 引数

#### TC-045: 隔離済み Docker 引数

| 項目 | 内容 |
| --- | --- |
| What | DockerArgs の セキュリティ。入力から得る結果・状態を検証。入力：digest 固定 image、network none。確認：read-only 等5制御が含まれ、禁止オプションなし |
| Why | 生成引数が最低限の隔離制御を含むため |
| Who | sandbox の Docker 引数責務。呼び出し元との境界は戻り値・出力ファイル |
| When | digest 固定 image、network none の条件で実行 |
| Where | `internal/sandbox/docker.go:DockerArgs` |
| How | Arrange: digest 固定 image、network none → Act: `DockerArgs` を呼ぶ → Assert: read-only 等5制御が含まれ、禁止オプションなし |
| 前提条件・入力 | digest 固定 image、network none |
| 実行内容・期待結果 | read-only 等5制御が含まれ、禁止オプションなし |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/sandbox/docker_test.go:TestHardenedDockerArgs` |

#### TC-046: タグのみの image を拒否

| 項目 | 内容 |
| --- | --- |
| What | DockerArgs の 入力バリデーション。入力から得る結果・状態を検証。入力：scanner:latest。確認：error |
| Why | 可変 image を使用しないため |
| Who | sandbox の Docker 引数責務。呼び出し元との境界は戻り値・出力ファイル |
| When | scanner:latest の条件で実行 |
| Where | `internal/sandbox/docker.go:DockerArgs` |
| How | Arrange: scanner:latest → Act: `DockerArgs` を呼ぶ → Assert: error |
| 前提条件・入力 | scanner:latest |
| 実行内容・期待結果 | error |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/sandbox/docker_test.go:TestRejectUnpinnedAndNetwork` |

#### TC-047: 未強制のネットワークを拒否

| 項目 | 内容 |
| --- | --- |
| What | DockerArgs の 入力バリデーション。入力から得る結果・状態を検証。入力：network restricted。確認：error |
| Why | 外部 proxy 強制なしの通信を許可しないため |
| Who | sandbox の Docker 引数責務。呼び出し元との境界は戻り値・出力ファイル |
| When | network restricted の条件で実行 |
| Where | `internal/sandbox/docker.go:DockerArgs` |
| How | Arrange: network restricted → Act: `DockerArgs` を呼ぶ → Assert: error |
| 前提条件・入力 | network restricted |
| 実行内容・期待結果 | error |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/sandbox/docker_test.go:TestRejectUnpinnedAndNetwork` |

#### TC-048: Docker socket 引数を検出

| 項目 | 内容 |
| --- | --- |
| What | ContainsForbidden の セキュリティ。入力から得る結果・状態を検証。入力：-v /var/run/docker.sock:/sock。確認：true |
| Why | ホストの Docker socket 露出を検出するため |
| Who | sandbox の Docker 引数責務。呼び出し元との境界は戻り値・出力ファイル |
| When | -v /var/run/docker.sock:/sock の条件で実行 |
| Where | `internal/sandbox/docker.go:ContainsForbidden` |
| How | Arrange: -v /var/run/docker.sock:/sock → Act: `ContainsForbidden` を呼ぶ → Assert: true |
| 前提条件・入力 | -v /var/run/docker.sock:/sock |
| 実行内容・期待結果 | true |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/sandbox/docker_test.go:TestForbiddenSockets` |

### 機密値マスク

#### TC-049: 既知 secret 原文を伏せて先頭を残す

| 項目 | 内容 |
| --- | --- |
| What | Text の セキュリティ。入力から得る結果・状態を検証。入力：AWS 形式の文字列。確認：原文なし、AKIA 接頭辞あり |
| Why | 調査可能性を保ちつつ secret 全文を漏らさないため |
| Who | secret の 機密値マスク責務。呼び出し元との境界は戻り値・出力ファイル |
| When | AWS 形式の文字列 の条件で実行 |
| Where | `internal/secret/mask.go:Text` |
| How | Arrange: AWS 形式の文字列 → Act: `Text` を呼ぶ → Assert: 原文なし、AKIA 接頭辞あり |
| 前提条件・入力 | AWS 形式の文字列 |
| 実行内容・期待結果 | 原文なし、AKIA 接頭辞あり |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/secret/mask_test.go:TestMaskKnownSecret` |

#### TC-050: 機密キーを一律伏せる

| 項目 | 内容 |
| --- | --- |
| What | Evidence の セキュリティ。入力から得る結果・状態を検証。入力：secret=top-secret、safe=ok。確認：secret は REDACTED、safe は ok |
| Why | キーで判定できる機密値を隠し無関係の値は保持するため |
| Who | secret の 機密値マスク責務。呼び出し元との境界は戻り値・出力ファイル |
| When | secret=top-secret、safe=ok の条件で実行 |
| Where | `internal/secret/mask.go:Evidence` |
| How | Arrange: secret=top-secret、safe=ok → Act: `Evidence` を呼ぶ → Assert: secret は REDACTED、safe は ok |
| 前提条件・入力 | secret=top-secret、safe=ok |
| 実行内容・期待結果 | secret は REDACTED、safe は ok |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/secret/mask_test.go:TestEvidenceSensitiveKeys` |

#### TC-051: 入れ子配列内の secret を伏せる

| 項目 | 内容 |
| --- | --- |
| What | Evidence の セキュリティ。入力から得る結果・状態を検証。入力：配列内の文字列と map の値に AWS 形式。確認：原文なし |
| Why | 入れ子証跡からの漏えいを防ぐため |
| Who | secret の 機密値マスク責務。呼び出し元との境界は戻り値・出力ファイル |
| When | 配列内の文字列と map の値に AWS 形式 の条件で実行 |
| Where | `internal/secret/mask.go:Evidence` |
| How | Arrange: 配列内の文字列と map の値に AWS 形式 → Act: `Evidence` を呼ぶ → Assert: 原文なし |
| 前提条件・入力 | 配列内の文字列と map の値に AWS 形式 |
| 実行内容・期待結果 | 原文なし |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/secret/mask_test.go:TestEvidenceMasksNestedArrays` |

### 横断・E2E

#### TC-052: 生成引数の隔離契約

| 項目 | 内容 |
| --- | --- |
| What | DockerArgs の セキュリティ。入力から得る結果・状態を検証。入力：digest 固定 image、network none。確認：必要な9制御あり、禁止8文字列なし |
| Why | 隔離引数の回帰を検出するため。実 Docker の隔離は検証しない |
| Who | tests の 横断・E2E責務。呼び出し元との境界は戻り値・出力ファイル |
| When | digest 固定 image、network none の条件で実行 |
| Where | `internal/sandbox/docker.go:DockerArgs` |
| How | Arrange: digest 固定 image、network none → Act: `DockerArgs` を呼ぶ → Assert: 必要な9制御あり、禁止8文字列なし |
| 前提条件・入力 | digest 固定 image、network none |
| 実行内容・期待結果 | 必要な9制御あり、禁止8文字列なし |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `tests/security_negative_test.go:TestIsolationContract` |

### 実データ結合

#### TC-053: 実スキャナ出力の正規化と BLOCK

| 項目 | 内容 |
| --- | --- |
| What | Parse / Evaluate / EvaluateOPA の E2E。入力から得る結果・状態を検証。入力：SECURITY_GATE_REAL_E2E_DIR に OSV/Trivy/Gitleaks JSON。確認：各出力に finding、3カテゴリ存在、secret 原文なし、Go 判定 BLOCK。OPA_TEST_BIN 時は OPA も BLOCK。入力未指定なら skip |
| Why | 実データ形式から判定までの接続を確認するため。スキャナ実行自体はこの Go テスト外 |
| Who | tests の 実データ結合責務。呼び出し元との境界は戻り値・出力ファイル |
| When | SECURITY_GATE_REAL_E2E_DIR に OSV/Trivy/Gitleaks JSON の条件で実行 |
| Where | `internal/normalize/normalize.go + internal/policy/policy.go:Parse / Evaluate / EvaluateOPA` |
| How | Arrange: SECURITY_GATE_REAL_E2E_DIR に OSV/Trivy/Gitleaks JSON → Act: `Parse / Evaluate / EvaluateOPA` を呼ぶ → Assert: 各出力に finding、3カテゴリ存在、secret 原文なし、Go 判定 BLOCK。OPA_TEST_BIN 時は OPA も BLOCK。入力未指定なら skip |
| 前提条件・入力 | SECURITY_GATE_REAL_E2E_DIR に OSV/Trivy/Gitleaks JSON |
| 実行内容・期待結果 | 各出力に finding、3カテゴリ存在、secret 原文なし、Go 判定 BLOCK。OPA_TEST_BIN 時は OPA も BLOCK。入力未指定なら skip |
| Mock / Stub / Fixture | 任意の実スキャナ JSON。未設定なら skip |
| 対応テストコード | `tests/real_scanner_e2e_test.go:TestRealScannerOutputsNormalizeAndBlock` |


#### TC-054: Windows 実コンテナの隔離

| 項目 | 内容 |
| --- | --- |
| What | セキュリティ・外部依存。Windows 実コンテナの隔離。入力：digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel。確認：socket 不可視、対象書込不可、metadata と公開ネットワーク到達不可、sentinel hash 不変 |
| Why | 隔離設定が実行時にも効くことを確かめるため。image と Docker が必要 |
| Who | `Docker / PowerShell` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel の条件で実行 |
| Where | `Docker / PowerShell` |
| How | Arrange: digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel → Act: 対象を実行 → Assert: socket 不可視、対象書込不可、metadata と公開ネットワーク到達不可、sentinel hash 不変 |
| 前提条件・入力 | digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel |
| 実行内容・期待結果 | socket 不可視、対象書込不可、metadata と公開ネットワーク到達不可、sentinel hash 不変 |
| Mock / Stub / Fixture | digest 固定 Docker image、Docker daemon、一時 sentinel |
| 対応テストコード | `tests/runtime-isolation.ps1:tests/runtime-isolation.ps1` |


#### TC-055: Linux 実コンテナの隔離

| 項目 | 内容 |
| --- | --- |
| What | セキュリティ・外部依存。Linux 実コンテナの隔離。入力：digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel。確認：socket 不可視、対象書込不可、metadata と公開ネットワーク到達不可、sentinel 内容不変 |
| Why | 隔離設定が Linux 実行時にも効くことを確かめるため。専用 CI と image が必要 |
| Who | `Docker / shell` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel の条件で実行 |
| Where | `Docker / shell` |
| How | Arrange: digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel → Act: 対象を実行 → Assert: socket 不可視、対象書込不可、metadata と公開ネットワーク到達不可、sentinel 内容不変 |
| 前提条件・入力 | digest 固定 SECURITY_GATE_TEST_IMAGE と sentinel |
| 実行内容・期待結果 | socket 不可視、対象書込不可、metadata と公開ネットワーク到達不可、sentinel 内容不変 |
| Mock / Stub / Fixture | digest 固定 Docker image、Docker daemon、一時 sentinel |
| 対応テストコード | `tests/runtime-isolation.sh:tests/runtime-isolation.sh` |


#### TC-056: スキャナ結果0件は ERROR【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系。スキャナ結果0件は ERROR。入力：ScannerRuns=nil。確認：ERROR と no scanner result の理由1件 |
| Why | 検査未実施を安全扱いしないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | ScannerRuns=nil の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: ScannerRuns=nil → Act: 対象を実行 → Assert: ERROR と no scanner result の理由1件 |
| 前提条件・入力 | ScannerRuns=nil |
| 実行内容・期待結果 | ERROR と no scanner result の理由1件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestNoScannerResultIsError` |
| 不足テストID | ADD-001 |

#### TC-057: FAILED は ERROR【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系。FAILED は ERROR。入力：StatusFailed。確認：ERROR、理由1件 |
| Why | 失敗を REVIEW 等へ弱めないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | StatusFailed の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: StatusFailed → Act: 対象を実行 → Assert: ERROR、理由1件 |
| 前提条件・入力 | StatusFailed |
| 実行内容・期待結果 | ERROR、理由1件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestScannerFailureStatuses/FAILED` |
| 不足テストID | ADD-002 |

#### TC-058: TIMEOUT は ERROR【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系。TIMEOUT は ERROR。入力：StatusTimeout。確認：ERROR、理由1件 |
| Why | 時間切れを REVIEW 等へ弱めないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | StatusTimeout の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: StatusTimeout → Act: 対象を実行 → Assert: ERROR、理由1件 |
| 前提条件・入力 | StatusTimeout |
| 実行内容・期待結果 | ERROR、理由1件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestScannerFailureStatuses/TIMEOUT` |
| 不足テストID | ADD-002 |

#### TC-059: PARTIAL は REVIEW【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系。PARTIAL は REVIEW。入力：StatusPartial。確認：REVIEW、理由1件 |
| Why | 不完全な結果に人手確認を要求するため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | StatusPartial の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: StatusPartial → Act: 対象を実行 → Assert: REVIEW、理由1件 |
| 前提条件・入力 | StatusPartial |
| 実行内容・期待結果 | REVIEW、理由1件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestScannerFailureStatuses/PARTIAL` |
| 不足テストID | ADD-002 |

#### TC-060: UNSUPPORTED は REVIEW【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系。UNSUPPORTED は REVIEW。入力：StatusUnsupported。確認：REVIEW、理由1件 |
| Why | 未対応の検査に人手確認を要求するため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | StatusUnsupported の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: StatusUnsupported → Act: 対象を実行 → Assert: REVIEW、理由1件 |
| 前提条件・入力 | StatusUnsupported |
| 実行内容・期待結果 | REVIEW、理由1件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestScannerFailureStatuses/UNSUPPORTED` |
| 不足テストID | ADD-002 |

#### TC-061: integrity は例外で免除不可【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限・セキュリティ。integrity は例外で免除不可。入力：integrity finding と有効例外。確認：BLOCK |
| Why | 整合性違反を例外で隠さないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | integrity finding と有効例外 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: integrity finding と有効例外 → Act: 対象を実行 → Assert: BLOCK |
| 前提条件・入力 | integrity finding と有効例外 |
| 実行内容・期待結果 | BLOCK |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionCannotOverrideSecurityInvariant/integrity` |
| 不足テストID | ADD-003 |

#### TC-062: prohibited capability は例外で免除不可【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限・セキュリティ。prohibited capability は例外で免除不可。入力：prohibited-capability finding と有効例外。確認：BLOCK |
| Why | 禁止能力を例外で隠さないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | prohibited-capability finding と有効例外 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: prohibited-capability finding と有効例外 → Act: 対象を実行 → Assert: BLOCK |
| 前提条件・入力 | prohibited-capability finding と有効例外 |
| 実行内容・期待結果 | BLOCK |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionCannotOverrideSecurityInvariant/prohibited_capability` |
| 不足テストID | ADD-003 |

#### TC-063: 高信頼 secret は例外で免除不可【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限・セキュリティ。高信頼 secret は例外で免除不可。入力：secret finding と有効例外。確認：BLOCK |
| Why | 秘密情報の露出を例外で許可しないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | secret finding と有効例外 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: secret finding と有効例外 → Act: 対象を実行 → Assert: BLOCK |
| 前提条件・入力 | secret finding と有効例外 |
| 実行内容・期待結果 | BLOCK |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionCannotOverrideSecurityInvariant/confirmed_secret` |
| 不足テストID | ADD-003 |

#### TC-064: MCP YARA は例外で免除不可【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限・セキュリティ。MCP YARA は例外で免除不可。入力：MCP YARA finding と有効例外。確認：BLOCK |
| Why | 悪性 MCP 検出を例外で許可しないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | MCP YARA finding と有効例外 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: MCP YARA finding と有効例外 → Act: 対象を実行 → Assert: BLOCK |
| 前提条件・入力 | MCP YARA finding と有効例外 |
| 実行内容・期待結果 | BLOCK |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionCannotOverrideSecurityInvariant/MCP_YARA` |
| 不足テストID | ADD-003 |

#### TC-065: ERROR は BLOCK より優先【追加】

| 項目 | 内容 |
| --- | --- |
| What | 状態遷移。ERROR は BLOCK より優先。入力：FAILED と高信頼 secret が同時発生。確認：ERROR、理由2件 |
| Why | 複合異常で最も厳しい決定と診断理由を保つため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | FAILED と高信頼 secret が同時発生 の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: FAILED と高信頼 secret が同時発生 → Act: 対象を実行 → Assert: ERROR、理由2件 |
| 前提条件・入力 | FAILED と高信頼 secret が同時発生 |
| 実行内容・期待結果 | ERROR、理由2件 |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestErrorTakesPriorityOverBlock` |
| 不足テストID | ADD-004 |

#### TC-066: 期限ちょうどの例外は無効【追加】

| 項目 | 内容 |
| --- | --- |
| What | 境界値。期限ちょうどの例外は無効。入力：例外 ExpiresAt=Now。確認：REVIEW |
| Why | 失効時刻以降に例外を適用しないため |
| Who | `internal/policy` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | 例外 ExpiresAt=Now の条件で実行 |
| Where | `internal/policy/policy.go:Evaluate` |
| How | Arrange: 例外 ExpiresAt=Now → Act: 対象を実行 → Assert: REVIEW |
| 前提条件・入力 | 例外 ExpiresAt=Now |
| 実行内容・期待結果 | REVIEW |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/policy/policy_test.go:TestExceptionExpiresAtBoundary` |
| 不足テストID | ADD-005 |

#### TC-067: Scorecard 閾値ちょうどは検出しない【追加】

| 項目 | 内容 |
| --- | --- |
| What | 境界値。Scorecard 閾値ちょうどは検出しない。入力：閾値7、score 6/7/8。確認：6 の finding だけ、MEDIUM |
| Why | 閾値の直前・一致・直後を区別するため |
| Who | `internal/normalize` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | 閾値7、score 6/7/8 の条件で実行 |
| Where | `internal/normalize/normalize.go:Scorecard` |
| How | Arrange: 閾値7、score 6/7/8 → Act: 対象を実行 → Assert: 6 の finding だけ、MEDIUM |
| 前提条件・入力 | 閾値7、score 6/7/8 |
| 実行内容・期待結果 | 6 の finding だけ、MEDIUM |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestScorecardThresholdBoundary` |
| 不足テストID | ADD-006 |

#### TC-068: Gitleaks fingerprint 欠落時の安定 ID【追加】

| 項目 | 内容 |
| --- | --- |
| What | 境界値・セキュリティ。Gitleaks fingerprint 欠落時の安定 ID。入力：Fingerprint なし、Secret あり。確認：2回の ID が一致し16桁、secret 原文なし |
| Why | 識別子欠落時も同じ検出を追跡し秘密を漏らさないため |
| Who | `internal/normalize` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | Fingerprint なし、Secret あり の条件で実行 |
| Where | `internal/normalize/normalize.go:Gitleaks` |
| How | Arrange: Fingerprint なし、Secret あり → Act: 対象を実行 → Assert: 2回の ID が一致し16桁、secret 原文なし |
| 前提条件・入力 | Fingerprint なし、Secret あり |
| 実行内容・期待結果 | 2回の ID が一致し16桁、secret 原文なし |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestGitleaksMissingFingerprintUsesStableID` |
| 不足テストID | ADD-007 |

#### TC-069: 未知の scanner 名を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション。未知の scanner 名を拒否。入力：scanner=unknown、妥当 JSON。確認：unsupported scanner error |
| Why | 未対応の形式を空結果として扱わないため |
| Who | `internal/normalize` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | scanner=unknown、妥当 JSON の条件で実行 |
| Where | `internal/normalize/normalize.go:Parse` |
| How | Arrange: scanner=unknown、妥当 JSON → Act: 対象を実行 → Assert: unsupported scanner error |
| 前提条件・入力 | scanner=unknown、妥当 JSON |
| 実行内容・期待結果 | unsupported scanner error |
| Mock / Stub / Fixture | テスト内データ。mock なし |
| 対応テストコード | `internal/normalize/normalize_test.go:TestUnsupportedScannerIsRejected` |
| 不足テストID | ADD-008 |

#### TC-070: 一致するスキャナ hash を許可【追加】

| 項目 | 内容 |
| --- | --- |
| What | 正常系。一致するスキャナ hash を許可。入力：実ファイルの SHA-256 を期待値に指定。確認：OK、Error 空、Actual 一致 |
| Why | 承認済み実体を使用可能にするため |
| Who | `internal/integrity` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | 実ファイルの SHA-256 を期待値に指定 の条件で実行 |
| Where | `internal/integrity/integrity.go:Verify` |
| How | Arrange: 実ファイルの SHA-256 を期待値に指定 → Act: 対象を実行 → Assert: OK、Error 空、Actual 一致 |
| 前提条件・入力 | 実ファイルの SHA-256 を期待値に指定 |
| 実行内容・期待結果 | OK、Error 空、Actual 一致 |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル。mock なし |
| 対応テストコード | `internal/integrity/integrity_test.go:TestVerifiedArtifact` |
| 不足テストID | ADD-009 |

#### TC-071: スキャナ実体が存在しない場合を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系。スキャナ実体が存在しない場合を拒否。入力：RuntimePath=missing。確認：OK=false、UNVERIFIED_SCANNER_ARTIFACT |
| Why | 実体不在を正常として扱わないため |
| Who | `internal/integrity` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | RuntimePath=missing の条件で実行 |
| Where | `internal/integrity/integrity.go:Verify` |
| How | Arrange: RuntimePath=missing → Act: 対象を実行 → Assert: OK=false、UNVERIFIED_SCANNER_ARTIFACT |
| 前提条件・入力 | RuntimePath=missing |
| 実行内容・期待結果 | OK=false、UNVERIFIED_SCANNER_ARTIFACT |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル。mock なし |
| 対応テストコード | `internal/integrity/integrity_test.go:TestMissingArtifactFailsClosed` |
| 不足テストID | ADD-009 |

#### TC-072: DB 成果物と hash が一致【追加】

| 項目 | 内容 |
| --- | --- |
| What | DB・ファイル。DB 成果物と hash が一致。入力：metadata と db.bin が一致。確認：Version/hash を返し error なし |
| Why | 承認済み DB キャッシュを使用可能にするため |
| Who | `internal/orchestrator` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | metadata と db.bin が一致 の条件で実行 |
| Where | `internal/orchestrator/orchestrator.go:verifyDB` |
| How | Arrange: metadata と db.bin が一致 → Act: 対象を実行 → Assert: Version/hash を返し error なし |
| 前提条件・入力 | metadata と db.bin が一致 |
| 実行内容・期待結果 | Version/hash を返し error なし |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル。mock なし |
| 対応テストコード | `internal/orchestrator/orchestrator_test.go:TestVerifyDBAcceptsMatchingArtifact` |
| 不足テストID | ADD-010 |

#### TC-073: DB 成果物改変を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | DB・異常系。DB 成果物改変を拒否。入力：metadata の hash と実ファイルが不一致。確認：DB hash mismatch error |
| Why | 改変された DB で検査しないため |
| Who | `internal/orchestrator` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | metadata の hash と実ファイルが不一致 の条件で実行 |
| Where | `internal/orchestrator/orchestrator.go:verifyDB` |
| How | Arrange: metadata の hash と実ファイルが不一致 → Act: 対象を実行 → Assert: DB hash mismatch error |
| 前提条件・入力 | metadata の hash と実ファイルが不一致 |
| 実行内容・期待結果 | DB hash mismatch error |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル。mock なし |
| 対応テストコード | `internal/orchestrator/orchestrator_test.go:TestVerifyDBRejectsHashMismatch` |
| 不足テストID | ADD-010 |

#### TC-074: DB 成果物の親ディレクトリ逸脱を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | DB・入力バリデーション。DB 成果物の親ディレクトリ逸脱を拒否。入力：Artifact=../outside.bin。確認：DB artifact escapes cache error |
| Why | キャッシュ外のファイルを DB として読まないため |
| Who | `internal/orchestrator` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | Artifact=../outside.bin の条件で実行 |
| Where | `internal/orchestrator/orchestrator.go:verifyDB` |
| How | Arrange: Artifact=../outside.bin → Act: 対象を実行 → Assert: DB artifact escapes cache error |
| 前提条件・入力 | Artifact=../outside.bin |
| 実行内容・期待結果 | DB artifact escapes cache error |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル。mock なし |
| 対応テストコード | `internal/orchestrator/orchestrator_test.go:TestVerifyDBRejectsEscapingArtifact` |
| 不足テストID | ADD-010 |

#### TC-075: 必須項目欠落の例外を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション。必須項目欠落の例外を拒否。入力：finding_id と scope のみの例外 JSON。確認：error 非 nil |
| Why | 承認情報が不完全な例外を採用しないため |
| Who | `internal/exception` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | finding_id と scope のみの例外 JSON の条件で実行 |
| Where | `internal/exception/exception.go:Load` |
| How | Arrange: finding_id と scope のみの例外 JSON → Act: 対象を実行 → Assert: error 非 nil |
| 前提条件・入力 | finding_id と scope のみの例外 JSON |
| 実行内容・期待結果 | error 非 nil |
| Mock / Stub / Fixture | t.TempDir() の一時ファイル。mock なし |
| 対応テストコード | `internal/exception/exception_test.go:TestLoadRejectsMissingRequiredFields` |
| 不足テストID | ADD-011 |

#### TC-076: 対象 scope の例外を適用【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限。対象 scope の例外を適用。入力：scope=t、期限は1秒後。確認：active=true |
| Why | 対象に一致する例外だけを適用するため |
| Who | `internal/exception` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | scope=t、期限は1秒後 の条件で実行 |
| Where | `internal/exception/exception.go:ActiveFor` |
| How | Arrange: scope=t、期限は1秒後 → Act: 対象を実行 → Assert: active=true |
| 前提条件・入力 | scope=t、期限は1秒後 |
| 実行内容・期待結果 | active=true |
| Mock / Stub / Fixture | テスト内の例外・時刻。mock なし |
| 対応テストコード | `internal/exception/exception_test.go:TestActiveForRequiresMatchingScopeAndUnexpiredTime/target_scope` |
| 不足テストID | ADD-011 |

#### TC-077: ワイルドカード scope の例外を適用【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限。ワイルドカード scope の例外を適用。入力：scope=*、期限は1秒後。確認：active=true |
| Why | 実装上の全対象例外を適用するため |
| Who | `internal/exception` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | scope=*、期限は1秒後 の条件で実行 |
| Where | `internal/exception/exception.go:ActiveFor` |
| How | Arrange: scope=*、期限は1秒後 → Act: 対象を実行 → Assert: active=true |
| 前提条件・入力 | scope=*、期限は1秒後 |
| 実行内容・期待結果 | active=true |
| Mock / Stub / Fixture | テスト内の例外・時刻。mock なし |
| 対応テストコード | `internal/exception/exception_test.go:TestActiveForRequiresMatchingScopeAndUnexpiredTime/wildcard_scope` |
| 不足テストID | ADD-011 |

#### TC-078: 他対象 scope の例外は無効【追加】

| 項目 | 内容 |
| --- | --- |
| What | 権限。他対象 scope の例外は無効。入力：scope=other、対象 t。確認：active=false |
| Why | 他対象の例外流用を防ぐため |
| Who | `internal/exception` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | scope=other、対象 t の条件で実行 |
| Where | `internal/exception/exception.go:ActiveFor` |
| How | Arrange: scope=other、対象 t → Act: 対象を実行 → Assert: active=false |
| 前提条件・入力 | scope=other、対象 t |
| 実行内容・期待結果 | active=false |
| Mock / Stub / Fixture | テスト内の例外・時刻。mock なし |
| 対応テストコード | `internal/exception/exception_test.go:TestActiveForRequiresMatchingScopeAndUnexpiredTime/different_scope` |
| 不足テストID | ADD-011 |

#### TC-079: 期限ちょうどの例外は ActiveFor で無効【追加】

| 項目 | 内容 |
| --- | --- |
| What | 境界値。期限ちょうどの例外は ActiveFor で無効。入力：ExpiresAt=Now。確認：active=false |
| Why | 失効境界で例外を延長しないため |
| Who | `internal/exception` の責務。呼び出し元との境界は戻り値または外部実行結果 |
| When | ExpiresAt=Now の条件で実行 |
| Where | `internal/exception/exception.go:ActiveFor` |
| How | Arrange: ExpiresAt=Now → Act: 対象を実行 → Assert: active=false |
| 前提条件・入力 | ExpiresAt=Now |
| 実行内容・期待結果 | active=false |
| Mock / Stub / Fixture | テスト内の例外・時刻。mock なし |
| 対応テストコード | `internal/exception/exception_test.go:TestActiveForRequiresMatchingScopeAndUnexpiredTime/expired_at_boundary` |
| 不足テストID | ADD-011 |



#### TC-080: 妥当な manifest を読み込む【追加】

| 項目 | 内容 |
| --- | --- |
| What | 正常系。妥当な manifest を読み込む。入力：必須項目・digest 固定 image・SHA256・有効日付を備えた1 scanner。確認：1件の trivy を返し error なし |
| Why | 妥当な承認 manifest を読み込めるため |
| Who | `internal/manifest` の入力・選択・実行引数の責務 |
| When | 必須項目・digest 固定 image・SHA256・有効日付を備えた1 scanner の条件で実行 |
| Where | `internal/manifest/manifest.go:Load` |
| How | Arrange: 必須項目・digest 固定 image・SHA256・有効日付を備えた1 scanner → Act: 対象関数を呼ぶ → Assert: 1件の trivy を返し error なし |
| 前提条件・入力 | 必須項目・digest 固定 image・SHA256・有効日付を備えた1 scanner |
| 実行内容・期待結果 | 1件の trivy を返し error なし |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/manifest/manifest_test.go:TestLoadAcceptsValidManifest` |
| 不足テストID | ADD-012 |

#### TC-081: 可変 worker image を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション・セキュリティ。可変 worker image を拒否。入力：worker_image=scanner:latest。確認：digest-pinned error |
| Why | 可変の実行 image を承認しないため |
| Who | `internal/manifest` の入力・選択・実行引数の責務 |
| When | worker_image=scanner:latest の条件で実行 |
| Where | `internal/manifest/manifest.go:Load` |
| How | Arrange: worker_image=scanner:latest → Act: 対象関数を呼ぶ → Assert: digest-pinned error |
| 前提条件・入力 | worker_image=scanner:latest |
| 実行内容・期待結果 | digest-pinned error |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/manifest/manifest_test.go:TestLoadRejectsUnpinnedWorkerImage` |
| 不足テストID | ADD-012 |

#### TC-082: scanner 名重複を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション。scanner 名重複を拒否。入力：同名 scanner 2件。確認：duplicate scanner error |
| Why | 承認項目の曖昧さを防ぐため |
| Who | `internal/manifest` の入力・選択・実行引数の責務 |
| When | 同名 scanner 2件 の条件で実行 |
| Where | `internal/manifest/manifest.go:Load` |
| How | Arrange: 同名 scanner 2件 → Act: 対象関数を呼ぶ → Assert: duplicate scanner error |
| 前提条件・入力 | 同名 scanner 2件 |
| 実行内容・期待結果 | duplicate scanner error |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/manifest/manifest_test.go:TestLoadRejectsDuplicateScanner` |
| 不足テストID | ADD-012 |

#### TC-083: 不正な成果物 hash を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション・セキュリティ。不正な成果物 hash を拒否。入力：SHA256 に大文字 Z を64文字。確認：artifact_sha256 error |
| Why | 整合性を検証できない manifest を拒否するため |
| Who | `internal/manifest` の入力・選択・実行引数の責務 |
| When | SHA256 に大文字 Z を64文字 の条件で実行 |
| Where | `internal/manifest/manifest.go:Load` |
| How | Arrange: SHA256 に大文字 Z を64文字 → Act: 対象関数を呼ぶ → Assert: artifact_sha256 error |
| 前提条件・入力 | SHA256 に大文字 Z を64文字 |
| 実行内容・期待結果 | artifact_sha256 error |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/manifest/manifest_test.go:TestLoadRejectsInvalidArtifactHash` |
| 不足テストID | ADD-012 |

#### TC-084: MCP static では MCP scanner だけ選択【追加】

| 項目 | 内容 |
| --- | --- |
| What | 正常系。MCP static では MCP scanner だけ選択。入力：Type=mcp-static。確認：mcp-scanner のみ |
| Why | 対象種別に対応する検査を選ぶため |
| Who | `internal/scanners` の入力・選択・実行引数の責務 |
| When | Type=mcp-static の条件で実行 |
| Where | `internal/scanners/scanners.go:Required` |
| How | Arrange: Type=mcp-static → Act: 対象関数を呼ぶ → Assert: mcp-scanner のみ |
| 前提条件・入力 | Type=mcp-static |
| 実行内容・期待結果 | mcp-scanner のみ |
| Mock / Stub / Fixture | t.TempDir() のローカルパス。Docker 実行なし |
| 対応テストコード | `internal/scanners/scanners_test.go:TestRequiredSelectsScannerByTargetType/MCP_static` |
| 不足テストID | ADD-013 |

#### TC-085: OSS の必須 scanner を選択【追加】

| 項目 | 内容 |
| --- | --- |
| What | 正常系。OSS の必須 scanner を選択。入力：Type=oss、Repo 空。確認：osv-scanner,trivy,gitleaks |
| Why | 標準の3検査を欠かさないため |
| Who | `internal/scanners` の入力・選択・実行引数の責務 |
| When | Type=oss、Repo 空 の条件で実行 |
| Where | `internal/scanners/scanners.go:Required` |
| How | Arrange: Type=oss、Repo 空 → Act: 対象関数を呼ぶ → Assert: osv-scanner,trivy,gitleaks |
| 前提条件・入力 | Type=oss、Repo 空 |
| 実行内容・期待結果 | osv-scanner,trivy,gitleaks |
| Mock / Stub / Fixture | t.TempDir() のローカルパス。Docker 実行なし |
| 対応テストコード | `internal/scanners/scanners_test.go:TestRequiredSelectsScannerByTargetType/OSS` |
| 不足テストID | ADD-013 |

#### TC-086: Repo 指定時に Scorecard を追加【追加】

| 項目 | 内容 |
| --- | --- |
| What | 正常系。Repo 指定時に Scorecard を追加。入力：Type=oss、Repo=org/repo。確認：標準3検査と scorecard |
| Why | リポジトリ指定時の検査追加を保証するため |
| Who | `internal/scanners` の入力・選択・実行引数の責務 |
| When | Type=oss、Repo=org/repo の条件で実行 |
| Where | `internal/scanners/scanners.go:Required` |
| How | Arrange: Type=oss、Repo=org/repo → Act: 対象関数を呼ぶ → Assert: 標準3検査と scorecard |
| 前提条件・入力 | Type=oss、Repo=org/repo |
| 実行内容・期待結果 | 標準3検査と scorecard |
| Mock / Stub / Fixture | t.TempDir() のローカルパス。Docker 実行なし |
| 対応テストコード | `internal/scanners/scanners_test.go:TestRequiredSelectsScannerByTargetType/OSS_with_repository` |
| 不足テストID | ADD-013 |

#### TC-087: 未 provision の worker を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系・セキュリティ。未 provision の worker を拒否。入力：image digest が0を64文字。確認：not been provisioned error |
| Why | 仮の image digest で検査しないため |
| Who | `internal/scanners` の入力・選択・実行引数の責務 |
| When | image digest が0を64文字 の条件で実行 |
| Where | `internal/scanners/scanners.go:DockerCommand` |
| How | Arrange: image digest が0を64文字 → Act: 対象関数を呼ぶ → Assert: not been provisioned error |
| 前提条件・入力 | image digest が0を64文字 |
| 実行内容・期待結果 | not been provisioned error |
| Mock / Stub / Fixture | t.TempDir() のローカルパス。Docker 実行なし |
| 対応テストコード | `internal/scanners/scanners_test.go:TestDockerCommandRejectsUnprovisionedWorker` |
| 不足テストID | ADD-013 |

#### TC-088: 対象外の MCP snapshot を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 異常系・セキュリティ。対象外の MCP snapshot を拒否。入力：Tools が Target 外の絶対パス。確認：inside target directory error |
| Why | 対象外のホストファイルをコンテナへ渡さないため |
| Who | `internal/scanners` の入力・選択・実行引数の責務 |
| When | Tools が Target 外の絶対パス の条件で実行 |
| Where | `internal/scanners/scanners.go:DockerCommand` |
| How | Arrange: Tools が Target 外の絶対パス → Act: 対象関数を呼ぶ → Assert: inside target directory error |
| 前提条件・入力 | Tools が Target 外の絶対パス |
| 実行内容・期待結果 | inside target directory error |
| Mock / Stub / Fixture | t.TempDir() のローカルパス。Docker 実行なし |
| 対応テストコード | `internal/scanners/scanners_test.go:TestDockerCommandRejectsMCPSnapshotOutsideTarget` |
| 不足テストID | ADD-013 |

#### TC-089: 有効な policy 設定を読み込む【追加】

| 項目 | 内容 |
| --- | --- |
| What | 正常系。有効な policy 設定を読み込む。入力：閾値・version・期限必須・fail_closed を設定。確認：設定を返し error なし |
| Why | 安全設定をロードできるため |
| Who | `internal/policy` の入力・選択・実行引数の責務 |
| When | 閾値・version・期限必須・fail_closed を設定 の条件で実行 |
| Where | `internal/policy/policy.go:LoadConfig` |
| How | Arrange: 閾値・version・期限必須・fail_closed を設定 → Act: 対象関数を呼ぶ → Assert: 設定を返し error なし |
| 前提条件・入力 | 閾値・version・期限必須・fail_closed を設定 |
| 実行内容・期待結果 | 設定を返し error なし |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/policy/config_test.go:TestLoadConfigAcceptsSecuritySettings` |
| 不足テストID | ADD-014 |

#### TC-090: fail_closed 無効の設定を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション・セキュリティ。fail_closed 無効の設定を拒否。入力：FailClosed=false。確認：must require error |
| Why | 失敗時に許可される設定を拒否するため |
| Who | `internal/policy` の入力・選択・実行引数の責務 |
| When | FailClosed=false の条件で実行 |
| Where | `internal/policy/policy.go:LoadConfig` |
| How | Arrange: FailClosed=false → Act: 対象関数を呼ぶ → Assert: must require error |
| 前提条件・入力 | FailClosed=false |
| 実行内容・期待結果 | must require error |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/policy/config_test.go:TestLoadConfigRequiresFailClosedAndExpiry/fail_closed_disabled` |
| 不足テストID | ADD-014 |

#### TC-091: 例外期限必須が無効の設定を拒否【追加】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション・セキュリティ。例外期限必須が無効の設定を拒否。入力：ExceptionsRequireExpiry=false。確認：must require error |
| Why | 無期限例外を許す設定を拒否するため |
| Who | `internal/policy` の入力・選択・実行引数の責務 |
| When | ExceptionsRequireExpiry=false の条件で実行 |
| Where | `internal/policy/policy.go:LoadConfig` |
| How | Arrange: ExceptionsRequireExpiry=false → Act: 対象関数を呼ぶ → Assert: must require error |
| 前提条件・入力 | ExceptionsRequireExpiry=false |
| 実行内容・期待結果 | must require error |
| Mock / Stub / Fixture | t.TempDir() の JSON ファイル。mock なし |
| 対応テストコード | `internal/policy/config_test.go:TestLoadConfigRequiresFailClosedAndExpiry/expiry_disabled` |
| 不足テストID | ADD-014 |



#### TC-092: manifest が不正な worker digest を拒否【追加・2026-09-26修正済み】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション・セキュリティ。SHA-256 digest 形式。入力：scanner@sha256:not-a-digest。確認：error。現状は nil |
| Why | SHA-256 digest 固定という設計上の承認条件を保証するため |
| Who | `internal/manifest` の image 承認責務 |
| When | scanner@sha256:not-a-digest が入力されたとき |
| Where | `internal/manifest/manifest.go:Load` |
| How | Arrange: scanner@sha256:not-a-digest → Act: 対象関数を呼ぶ → Assert: error。現状は nil |
| 前提条件・入力 | scanner@sha256:not-a-digest |
| 実行内容・期待結果 | error。現状は nil |
| Mock / Stub / Fixture | テスト内データ・一時ディレクトリ。mock なし |
| 対応テストコード | `internal/manifest/manifest_test.go:TestLoadRejectsMalformedWorkerDigest` |
| 不足テストID | ADD-015 |

#### TC-093: Docker 引数生成が不正な image digest を拒否【追加・2026-09-26修正済み】

| 項目 | 内容 |
| --- | --- |
| What | 入力バリデーション・セキュリティ。SHA-256 digest 形式。入力：scanner@sha256:not-a-digest。確認：error。現状は nil |
| Why | 不正な image 参照で隔離 worker を起動しないため |
| Who | `internal/sandbox` の image 承認責務 |
| When | scanner@sha256:not-a-digest が入力されたとき |
| Where | `internal/sandbox/docker.go:DockerArgs` |
| How | Arrange: scanner@sha256:not-a-digest → Act: 対象関数を呼ぶ → Assert: error。現状は nil |
| 前提条件・入力 | scanner@sha256:not-a-digest |
| 実行内容・期待結果 | error。現状は nil |
| Mock / Stub / Fixture | テスト内データ・一時ディレクトリ。mock なし |
| 対応テストコード | `internal/sandbox/docker_test.go:TestRejectMalformedImageDigest` |
| 不足テストID | ADD-015 |

## 不足テストケース（追加前の分析）

以下は実装を根拠に特定した。各ケースの期待結果を追加前に定め、上の【追加】テストへ反映した。

### ADD-001: 結果0件の失敗クローズ

- 対象：`policy.Evaluate`
- 分類：異常系
- 前提条件・入力：ScannerRuns=nil
- 実行内容：対象関数へ入力する
- 期待結果：ERROR と理由
- 不足していると判断した理由：検査未実施の許可防止
- 対応する実装コード：`internal/policy/policy.go:Evaluate の len==0`
- 既存テストでカバーできていない理由：既存は COMPLETE 1件のみ
- 優先度：High
- 実装後テストID：TC-056

### ADD-002: 4種の非完了ステータスの厳密判定

- 対象：`policy.Evaluate`
- 分類：異常系
- 前提条件・入力：FAILED/TIMEOUT/PARTIAL/UNSUPPORTED
- 実行内容：対象関数へ入力する
- 期待結果：前2者 ERROR、後2者 REVIEW
- 不足していると判断した理由：弱い ALLOW 以外の assertion を補強
- 対応する実装コード：`internal/policy/policy.go:Evaluate の status switch`
- 既存テストでカバーできていない理由：TC-018〜021 は ALLOW 以外のみ
- 優先度：High
- 実装後テストID：TC-057〜060

### ADD-003: 安全上の非免除カテゴリ

- 対象：`policy.Evaluate`
- 分類：権限・セキュリティ
- 前提条件・入力：integrity/prohibited-capability/secret/MCP YARA と有効例外
- 実行内容：対象関数へ入力する
- 期待結果：全て BLOCK
- 不足していると判断した理由：例外による安全境界の迂回防止
- 対応する実装コード：`internal/policy/policy.go:Evaluate の nonOverride`
- 既存テストでカバーできていない理由：例外ありの既存ケースは脆弱性のみ
- 優先度：High
- 実装後テストID：TC-061〜064

### ADD-004: 判定の優先順位

- 対象：`policy.Evaluate`
- 分類：異常系・状態遷移
- 前提条件・入力：FAILED と secret が同時発生
- 実行内容：対象関数へ入力する
- 期待結果：ERROR、理由2件
- 不足していると判断した理由：複合条件の判定と診断理由保持
- 対応する実装コード：`internal/policy/policy.go:Evaluate の rank/set`
- 既存テストでカバーできていない理由：単独条件のみ
- 優先度：High
- 実装後テストID：TC-065

### ADD-005: 例外の期限一致

- 対象：`policy.Evaluate`
- 分類：境界値
- 前提条件・入力：ExpiresAt=Now
- 実行内容：対象関数へ入力する
- 期待結果：REVIEW
- 不足していると判断した理由：期限ちょうどの免除防止
- 対応する実装コード：`internal/exception/exception.go:ActiveFor の now.Before`
- 既存テストでカバーできていない理由：既存は前後だけ
- 優先度：High
- 実装後テストID：TC-066

### ADD-006: Scorecard 閾値境界

- 対象：`normalize.Scorecard`
- 分類：境界値
- 前提条件・入力：閾値7、6/7/8
- 実行内容：対象関数へ入力する
- 期待結果：6のみ検出
- 不足していると判断した理由：閾値の off-by-one 防止
- 対応する実装コード：`internal/normalize/normalize.go:Scorecard の >= threshold`
- 既存テストでカバーできていない理由：既存は2と9のみ
- 優先度：Medium
- 実装後テストID：TC-067

### ADD-007: Gitleaks の fallback ID

- 対象：`normalize.Gitleaks`
- 分類：正常系・境界値
- 前提条件・入力：Fingerprint 欠落
- 実行内容：対象関数へ入力する
- 期待結果：安定 ID と秘密情報の非漏えい
- 不足していると判断した理由：ID 欠損時の同定と漏えい防止
- 対応する実装コード：`internal/normalize/normalize.go:Gitleaks の id==empty`
- 既存テストでカバーできていない理由：既存は Fingerprint あり
- 優先度：Medium
- 実装後テストID：TC-068

### ADD-008: 未対応 scanner

- 対象：`normalize.Parse`
- 分類：入力バリデーション
- 前提条件・入力：scanner=unknown
- 実行内容：対象関数へ入力する
- 期待結果：error
- 不足していると判断した理由：形式不明の空結果化防止
- 対応する実装コード：`internal/normalize/normalize.go:Parse の default`
- 既存テストでカバーできていない理由：既存は既知 scanner のみ
- 優先度：Medium
- 実装後テストID：TC-069

### ADD-009: scanner 実体の成功・欠損

- 対象：`integrity.Verify`
- 分類：正常系・異常系
- 前提条件・入力：一致 hash / 欠損ファイル
- 実行内容：対象関数へ入力する
- 期待結果：OK / UNVERIFIED
- 不足していると判断した理由：検証可能な実体と欠損の境界
- 対応する実装コード：`internal/integrity/integrity.go:Verify の Open と hash 比較`
- 既存テストでカバーできていない理由：既存は不一致だけ
- 優先度：High
- 実装後テストID：TC-070〜071

### ADD-010: DB 成果物の一致・改変・逸脱

- 対象：`orchestrator.verifyDB`
- 分類：DB・セキュリティ
- 前提条件・入力：一致 hash / 不一致 / ../ 参照
- 実行内容：対象関数へ入力する
- 期待結果：成功 / hash error / 逸脱 error
- 不足していると判断した理由：信頼できる DB だけを使うため
- 対応する実装コード：`internal/orchestrator/orchestrator.go:verifyDB`
- 既存テストでカバーできていない理由：既存テストなし
- 優先度：High
- 実装後テストID：TC-072〜074

### ADD-011: 例外 JSON と対象・期限

- 対象：`exception.Load/ActiveFor`
- 分類：入力検証・権限
- 前提条件・入力：必須欠落 / 一致 / * / 不一致 / 期限一致
- 実行内容：対象関数へ入力する
- 期待結果：拒否 / true / true / false / false
- 不足していると判断した理由：不完全・対象外・失効例外の流用防止
- 対応する実装コード：`internal/exception/exception.go:Load/ActiveFor`
- 既存テストでカバーできていない理由：単体テストなし。policy の有効・期限切れだけ
- 優先度：High
- 実装後テストID：TC-075〜079

### ADD-012: manifest の承認条件

- 対象：`manifest.Load`
- 分類：正常系 / 入力バリデーション / セキュリティ
- 前提条件・入力：妥当な1件、可変 image、同名重複、不正 SHA-256 の各 JSON
- 実行内容：各 manifest を `Load` する
- 期待結果：妥当な1件のみ成功し、他は理由付き error
- 不足していると判断した理由：スキャナ承認情報が検査前の信頼境界になるため
- 対応する実装コード：`internal/manifest/manifest.go:Load`
- 既存テストでカバーできていない理由：manifest のテストファイルが存在しなかった
- 優先度：High
- 実装後テストID：TC-080〜083

### ADD-013: 必須スキャナと MCP snapshot の制約

- 対象：`scanners.Required` / `scanners.DockerCommand`
- 分類：正常系 / 異常系 / セキュリティ
- 前提条件・入力：MCP/OSS/Repo ありの要求、未 provision の image、対象外 snapshot
- 実行内容：必要スキャナの列挙または Docker 引数生成
- 期待結果：対象ごとの必要スキャナ、image/snapshot の拒否
- 不足していると判断した理由：検査漏れと対象外ファイルのマウントを防ぐため
- 対応する実装コード：`internal/scanners/scanners.go:Required` / `DockerCommand`
- 既存テストでカバーできていない理由：scanners パッケージのテストファイルが存在しなかった
- 優先度：High
- 実装後テストID：TC-084〜088

### ADD-014: ポリシー設定の fail-closed 条件

- 対象：`policy.LoadConfig`
- 分類：正常系 / 入力バリデーション / セキュリティ
- 前提条件・入力：妥当な設定、fail_closed=false、exceptions_require_expiry=false
- 実行内容：設定 JSON を読み込む
- 期待結果：妥当な設定のみ成功し、安全条件を外した設定は拒否
- 不足していると判断した理由：判定前の設定で fail-closed と期限必須を解除させないため
- 対応する実装コード：`internal/policy/policy.go:LoadConfig`
- 既存テストでカバーできていない理由：設定読込のテストがなかった
- 優先度：High
- 実装後テストID：TC-089〜091

### ADD-015: SHA-256 image digest の形式

- 対象：`manifest.Load` / `sandbox.DockerArgs`
- 分類：入力バリデーション / セキュリティ
- 前提条件・入力：`scanner@sha256:not-a-digest`
- 実行内容：manifest を読み込み、同じ形式の image で Docker 引数を生成する
- 期待結果：両方で error を返す
- 不足していると判断した理由：`SECURITY.md` と `docs/detailed-design.md` は digest 固定を条件とし、実隔離スクリプトは64文字の16進 SHA-256 を検査するため
- 対応する実装コード：`internal/manifest/manifest.go:Load` / `internal/sandbox/docker.go:DockerArgs`
- 既存テストでカバーできていない理由：タグのみの拒否はあるが、`@sha256:` の後ろが不正なケースはなかった
- 優先度：High
- 実装後テストID：TC-092〜093。初回実行時は失敗し、2026-09-26の修正後は成功

## 実装とテストの対応

「テスト済み」は、その条件を区別する assertion がある場合に限る。

| 実装上の条件・処理 | 実装箇所 | 対応 TC | 状態 |
| --- | --- | --- | --- |
| OSV CVSS 数値、database_specific HIGH、fixed | normalize.go:OSV | 001, 002 | テスト済み |
| Trivy 3カテゴリ、secret マスク | normalize.go:Trivy | 003, 004 | カテゴリ個別のフィールド値は未検証 |
| Gitleaks fingerprint 有無 | normalize.go:Gitleaks | 005, 068 | テスト済み |
| Scorecard 閾値未満・一致・超過 | normalize.go:Scorecard | 006, 067 | テスト済み |
| MCP UNSAFE / YARA | normalize.go:walkMCP | 007 | 件数のみ。各フィールド・代替形状は未検証 |
| 不正 JSON、必須キー欠落、未知 scanner | normalize.go:Parse ほか | 008〜013, 069 | テスト済み |
| 重要度各表記、未知表記 | normalize.go:Severity | 014〜016 | 列挙した3種類のみ |
| スキャナ結果0件、各 status | policy.go:Evaluate | 017〜021, 056〜060 | テスト済み |
| 整合性 error code | policy.go:Evaluate | なし | 未テスト |
| DB 鮮度と設定値 | policy.go:Evaluate | 025, 027 | 期限ちょうどは未テスト |
| アドバイザリ日時欠落・期限超過 | policy.go:Evaluate / main.rego | 034 | OPA の欠落のみ。Go の期限境界は未テスト |
| 例外の適用・失効・非免除 | exception.go:ActiveFor / policy.go:Evaluate | 023, 024, 061〜064, 066, 076〜079 | 主要条件をテスト済み |
| ERROR > BLOCK > REVIEW、理由収集 | policy.go:Evaluate | 065 | ERROR と BLOCK の組合せのみ |
| OPA の各決定と例外 | policies/main.rego | 029〜037 | 主要条件をテスト済み |
| OPA の HASH_MISMATCH 単独 error code | policies/main.rego | なし | 未テスト。Go と条件が異なる可能性 |
| OPA CLI の正常応答 | policy.go:EvaluateOPA | 028 | OPA_TEST_BIN がない環境では skip。異常応答未テスト |
| scanner 実体の一致・不一致・欠損 | integrity.go:Verify | 039, 070, 071 | テスト済み |
| DB metadata・hash・パス逸脱 | orchestrator.go:verifyDB | 072〜074 | 必須 metadata 欠損や symlink は未テスト |
| Docker 引数と実 runtime | sandbox.go:DockerArgs / runtime-isolation.* | 045〜048, 052, 054, 055 | 引数はテスト済み。runtime は環境依存 |
| timeout・起動失敗・出力上限 | runner.go:Run | 042〜044 | 標準エラー上限・環境変数隔離は未テスト |
| レポート mask・symlink 拒否 | report.go:Write | 040, 041 | テスト済み。Windows の置換中の障害は未テスト |
| 監査ハッシュ連鎖 | audit.go:Append | 038 | 連鎖参照のみ。改ざん検知・失敗時は未テスト |
| 例外 JSON 必須検証・scope・期限 | exception.go:Load / ActiveFor | 075〜079 | 主要条件をテスト済み |
| manifest の正常・可変 image・重複・不正 hash | manifest.go:Load | 080〜083 | 列挙した条件はテスト済み。残りの検証分岐は未テスト |
| worker image の不正 SHA-256 digest | manifest.go:Load / docker.go:DockerArgs | 092, 093 | 2026-09-26修正後に成功。初回は`@sha256:`の存在だけで受理していた |
| スキャナ選択、未 provision image、対象外 snapshot | scanners.go:Required / DockerCommand | 084〜088 | 列挙した条件はテスト済み。生成引数の全 variant は未テスト |
| 安全な policy 設定と必須フラグ | policy.go:LoadConfig | 089〜091 | 列挙した条件はテスト済み。閾値境界は未テスト |
| Scan 全体と CLI | orchestrator.go:Scan / main.go | なし | 統合テスト不足 |

## 追加しなかった不足候補と要確認事項

- `manifest.Load`、`scanners.DockerCommand` の残る分岐と `orchestrator.Scan`、CLI の全体連携：未テストでリスクが残る。実スキャナ・Docker・承認済み成果物・OPA への依存があり、主要経路を検証するには独立した統合 fixture と実行環境が必要。今回は実装から単独で期待値を確定できる条件を追加した。
- OPA と Go の判定同値性：`HASH_MISMATCH` の扱い、および未設定ポリシー値の扱いが実装上異なる可能性がある。どちらを正とするかは要確認。実運用では OPA の決定が採用されるため、単なる Go 側の値への合わせ込みはしない。
- DB 成果物・スキャナ実体の symlink 追跡：どの信頼境界で symlink を禁止するかは要確認。現在の `verifyDB` と `Verify` は通常ファイルを開いて hash を比較する。
- E2E 実行の外部依存：実 scanner JSON、OPA、Docker、digest 固定 image を供給する環境が必要。テストコードだけでは実サービス・コンテナ実行の保証にならない。

## テスト設計上の懸念

- `TestTrivy` と `TestMCP` は主に件数を確認するため、個々の ID・重要度・カテゴリ・証跡の取り違えを検出しにくい。
- `TestFailuresNeverAllow` は許可されないことだけを確認していた。追加の `TestScannerFailureStatuses` が決定種別を固定する。
- `TestAppendHashChain` は前後の hash 参照だけを確認し、保存済み行の hash 再計算や改ざん拒否は確認しない。
- Go テストは mock が少なく振る舞いを直接確認する。一方、隔離引数のテストは Docker が実際に隔離することを保証しない。
- `TestTimeout` は OS のプロセス起動時間と 50ms の期限に依存し、遅い環境で起動前に時間切れとなる可能性がある。意図する「時間切れを返す」は確認できるが実行中 timeout との差は確認できない。
- テスト間の共有可変状態は見つからなかった。固定時刻と `t.TempDir()` の利用で追加テストの実行順序依存を避けた。

## 最終評価

### 現在テストされている内容

- 正規化の代表入力、形式不正、閾値、秘密情報マスク。
- ネイティブ・OPA の主要判定、例外の適用/失効、検査失敗、DB 鮮度。
- scanner と DB の hash、Docker 隔離引数、runner 制限、レポートと監査ログの基本動作。

### 当初不足していた内容と今回追加したテスト

| ADD-ID | 対象ファイル | 追加した内容 |
| --- | --- | --- |
| ADD-001 | `internal/policy/policy.go` | 結果0件の失敗クローズ（TC-056） |
| ADD-002 | `internal/policy/policy.go` | 4種の非完了ステータスの厳密判定（TC-057〜060） |
| ADD-003 | `internal/policy/policy.go` | 安全上の非免除カテゴリ（TC-061〜064） |
| ADD-004 | `internal/policy/policy.go` | 判定の優先順位（TC-065） |
| ADD-005 | `internal/exception/exception.go` | 例外の期限一致（TC-066） |
| ADD-006 | `internal/normalize/normalize.go` | Scorecard 閾値境界（TC-067） |
| ADD-007 | `internal/normalize/normalize.go` | Gitleaks の fallback ID（TC-068） |
| ADD-008 | `internal/normalize/normalize.go` | 未対応 scanner（TC-069） |
| ADD-009 | `internal/integrity/integrity.go` | scanner 実体の成功・欠損（TC-070〜071） |
| ADD-010 | `internal/orchestrator/orchestrator.go` | DB 成果物の一致・改変・逸脱（TC-072〜074） |
| ADD-011 | `internal/exception/exception.go` | 例外 JSON と対象・期限（TC-075〜079） |
| ADD-012 | `internal/manifest/manifest.go` | manifest の承認条件（TC-080〜083） |
| ADD-013 | `internal/scanners/scanners.go` | スキャナ選択と snapshot 制約（TC-084〜088） |
| ADD-014 | `internal/policy/policy.go` | policy 設定の必須フラグ（TC-089〜091） |
| ADD-015 | `internal/manifest/manifest.go`・`internal/sandbox/docker.go` | 不正 SHA-256 image digest の拒否（TC-092〜093）。2026-09-26修正後に成功 |

### 残るリスク

- `orchestrator.Scan` 全体、manifest / DockerCommand の残る検証分岐、CLI の各異常経路は未検証。
- `scripts/update-security-data.ps1`、`scripts/admit-security-data.ps1`、`scripts/verify-scanners.ps1` の運用フローも自動テストがない。外部取得・承認・実行環境との結合を別途検証する必要がある。
- Docker 実隔離と実スキャナ実行は専用環境で再確認が必要。実スキャナ出力の Go テストは環境変数がなければ skip される。
- Go/OPA 間の条件差は要確認。両者の完全な同値性は保証されない。
- 不正な worker image digest の受理は2026-09-26に修正し、TC-092/093の成功を確認した。

### 追加テストで確認した実装上の不具合（2026-09-26修正済み）

- 失敗したテスト：`TestLoadRejectsMalformedWorkerDigest`、`TestRejectMalformedImageDigest`。
- 期待する仕様：SHA-256 image digest の固定。不正な `scanner@sha256:not-a-digest` は拒否する。根拠は `SECURITY.md`、`docs/detailed-design.md` の digest 固定条件、および `tests/runtime-isolation.ps1` の64文字16進形式チェック。
- 初回実行時の挙動：`manifest.Load` と `sandbox.DockerArgs` は error を返さず受理した。2026-09-26に64桁の小文字16進digestを検証するよう修正した。
- 実装箇所：`internal/manifest/manifest.go:Load` と `internal/sandbox/docker.go:DockerArgs` の `strings.Contains(..., "@sha256:")` 判定。
- 判断：テスト側の問題ではなく実装側の形式検証不足。期待値は変更せず、2026-09-26にproduction codeを修正した。

### テスト実行結果

実行環境：Windows amd64。Go 1.24.10 と OPA 1.20.2 を作業領域の無視対象 `var/` に配置した。

| 順序 | コマンド（主要部） | 結果 | 対象数・成功・失敗・skip |
| --- | --- | --- | --- |
| 1 | `go test -count=1 -v ./internal/policy ./internal/normalize ./internal/integrity ./internal/orchestrator ./internal/exception` | 成功 | 変更5パッケージ。OPA_TEST_BIN 未設定のため連携テスト1件 skip |
| 2 | `go test -count=1 -v ./internal/manifest ./internal/scanners ./internal/policy` | 成功 | 追加した信頼境界の3パッケージ。OPA_TEST_BIN 未設定のため連携テスト1件 skip |
| 3 | `go test -count=1 ./internal/...` | 成功 | TC-092/093 を追加する前の全 internal パッケージ |
| 4 | `opa test policies --fail-on-empty` | 成功 | Rego 9件成功、0失敗、0 skip |
| 5 | `go test -count=1 -run 'TestLoadRejectsMalformedWorkerDigest|TestRejectMalformedImageDigest' ./internal/manifest ./internal/sandbox` | 2件失敗 | 対象2件中0成功、2失敗、0 skip |
| 6 | `OPA_TEST_BIN=var/opa_windows_amd64.exe SECURITY_GATE_REAL_E2E_DIR=var/e2e-output go test -json -count=1 ./...` | 2件失敗 | Go トップレベル57件中54成功、2失敗、1 skip。サブテスト17件成功 |
| 7 | `go vet ./...` | 成功 | 指摘なし |

最終 Go 実行で失敗したのは TC-092/093。skip されたのは `TestWriteRejectsSymlinkDestination` で、Windows の symlink 作成権限がないため。実スキャナ出力 E2E と OPA CLI 連携は最終実行で成功した。実スキャナの新規起動と Docker の実隔離スクリプトは実行していない。この環境では Docker API への接続が permission denied だった。

最初の `go test ./...` は、取得した Go ツールチェーンをリポジトリ内 `var/toolchain` に展開したため Go 自身のソースまで探索して panic した。無視対象内のツールチェーンに独立した `go.mod` を置いて探索対象から外し、TC-092/093 追加前の全体実行は成功した。この panic はプロダクションコードの失敗ではない。
