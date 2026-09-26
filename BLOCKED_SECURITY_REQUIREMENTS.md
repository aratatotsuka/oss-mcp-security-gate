# Blocked Security Requirements

確認日: 2026-09-24

以下はsource codeだけでは安全に確定できず、deployment ownerの管理基盤・承認が必要です。回避策として安全条件を弱めていません。

## BSR-001 Internal worker image admission

状態: BLOCKED_SECURITY_REQUIREMENT

OSV-Scanner、Trivy、Gitleaks、Scorecard、Cisco MCP Scannerの内部worker image registry/digestが提供されていません。配布manifestは64桁zero digest sentinelを持ち、CLIは実行を拒否します。Update Pipelineで公式artifactのchecksum/署名/provenance/advisoryを確認し、internal immutable registryへmirrorして実digestを承認する必要があります。

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
