# Security Policy

## Supported configuration

このrepositoryのMVPは、`config/scanners.yaml`で承認されたversion、digest、policy versionの組合せだけを対象とします。`latest`、未検証binary、tag-only image、期限切れDB/advisory reviewはsupported configurationではありません。

## Reporting a vulnerability

公開issueへSecret、exploit、未修正脆弱性の詳細を投稿しないでください。組織のprivate security reporting channelへ、影響version、再現条件、最小限のredacted log、推奨embargo期間を送ってください。連絡先はdeployment ownerがこの節に設定してください。

## Scanner compromise response

1. 該当Scanner/version/digestをmanifestとinternal registryでdenyする。
2. Scan jobを停止し、過去reportを「再評価必要」とmarkする。過去のALLOWも信用しない。
3. artifact、DB、worker image、update worker log、transparency logを保全する。Secretは保全logにも残さない。
4. clean update workerで別versionを公式一次情報から再取得し、checksum、署名、provenance、advisoryを再検証する。
5. policyとfixtureを更新し、全test後に新digestを承認する。
6. compromised期間のtargetを再scanし、利用者へ影響範囲を通知する。

## Security invariants

- ScannerとTargetを信用しない。
- Network default deny。
- Target codeを実行しない。
- integrity、parse、timeout、OPAの失敗をALLOWへ変換しない。
- production credentialをworkerへ渡さない。
- secret raw valueをreport/audit/logへ保存しない。

Invariantを満たせない環境では、機能を弱めず `UNSUPPORTED_SECURITY_REQUIREMENT` とします。
