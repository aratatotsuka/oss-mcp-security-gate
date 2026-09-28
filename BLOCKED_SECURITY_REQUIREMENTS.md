# Blocked Security Requirements

確認日: 2026-09-28

以下は組織の厳格な署名・provenance基準で残る要件です。別途追加したローカル配備は公式HTTPSのdigest照合方式であり、この基準を満たしたとは扱いません。

## BSR-001 Internal worker image admission

状態: BLOCKED_SECURITY_REQUIREMENT

OSV-Scanner、Trivy、Gitleaks、Scorecard、Cisco MCP Scannerの内部worker image registry/digestが提供されていません。配布manifestは64桁zero digest sentinelを持ち、CLIは実行を拒否します。Update Pipelineで公式artifactのchecksum/署名/provenance/advisoryを確認し、internal immutable registryへmirrorして実digestを承認する必要があります。

ローカルのOSS配備では`deploy-oss.ps1`が実imageを作成し、同一Docker engineの不変image IDを記録できます。OSV・Trivy・Gitleaks・OPAの準備用環境で実スキャンを確認済みです。ただし署名・provenance検証と組織のregistry admissionは未実装で、この要件の全面解決ではありません。

## BSR-002 Cisco MCP Scanner Python base and lock

状態: BLOCKED_SECURITY_REQUIREMENT

Cisco MCP Scanner 4.8.4 wheel自体のPyPI attestationは確認済みですが、完全なtransitive dependency hash lockと承認済みPython base imageは組織固有です。未確定のためstatic/YARA workerはprovisionされません。

## BSR-003 Scorecard restricted egress

状態: UNSUPPORTED_SECURITY_REQUIREMENT

この端末にはGitHub APIだけをFQDN/identity単位で強制するproxy/firewallがありません。Docker networkだけでは宛先制限を証明できないため、Scorecard実行を拒否します。

## BSR-004 Runtime isolation test

状態: RESOLVED_FOR_LOCAL_E2E

Docker Desktop Linux engine上でdigest固定BusyBoxを使い、`network=none`、read-only root/target、非root、capability全drop、no-new-privileges、socket非公開、metadata/public Internet遮断、対象hash不変を確認した。再実行用に`tests/runtime-isolation.ps1`と`tests/runtime-isolation.sh`を保持する。本番Linux worker/CIでの継続試験は引き続き必要。

## BSR-005 Gitleaks provenance

状態: REVIEW REQUIRED

公式release checksumとSecurity Policyは確認できますが、採用versionについてOSV-Scannerと同等のdocumented SLSA verification pathを確認できませんでした。production admissionには組織の明示的risk acceptanceまたは追加の再現build/署名verificationが必要です。

## BSR-006 Offline DB cache wiring and bundle admission

状態: BLOCKED_SECURITY_REQUIREMENT

配線の状態: RESOLVED_FOR_LOCAL_OSS。`deploy-oss.ps1`でOSV ecosystem別DB、Trivyの脆弱性DB・checks、任意のJava DBを取得・配置し、世代ごとの全ファイルhashを記録・検証します。OSV 2.6.0のSCALIBR参照先を明示し、Trivyの解析cacheをメモリに置くことでDBを読み取り専用のまま使います。Go fixtureの実スキャンではOSV・Trivy・GitleaksがすべてCOMPLETE、OPA判定とレポート出力が成功しました。Java DBの実スキャンと全ecosystemのcoverageは未確認です。

DBの取得元は公式HTTPS/公式Trivy配布先ですが、publisher署名の検証は行いません。全ファイルhashは取得後の変更を検知するもので、配布元侵害への真正性の保証ではありません。組織で必要な追加検証は残ります。
