package security_gate_test

import rego.v1
import data.security_gate

base := {"now":"2026-09-24T00:00:00Z","target_id":"t","scanner_runs":[{"scanner":"osv-scanner","status":"COMPLETE","advisory_checked_at":"2026-09-24T00:00:00Z"}],"findings":[],"exceptions":[]}

test_allow_clean_complete if { security_gate.result with input as base == {"decision":"ALLOW","reasons":[]} }
test_error_on_failure if { security_gate.result.decision with input as object.union(base,{"scanner_runs":[{"scanner":"trivy","status":"FAILED"}]}) == "ERROR" }
test_block_secret if { security_gate.result.decision with input as object.union(base,{"findings":[{"finding_id":"secret-1","category":"secret","confidence":"HIGH","severity":"HIGH"}]}) == "BLOCK" }
test_review_high_cve if { security_gate.result.decision with input as object.union(base,{"findings":[{"finding_id":"CVE-1","category":"vulnerability","confidence":"HIGH","severity":"HIGH"}]}) == "REVIEW" }
test_review_stale_db if { security_gate.result.decision with input as object.union(base,{"scanner_runs":[{"scanner":"trivy","status":"COMPLETE","advisory_checked_at":"2026-09-24T00:00:00Z","db_updated_at":"2026-09-20T00:00:00Z"}]}) == "REVIEW" }
test_review_missing_advisory if { security_gate.result.decision with input as object.union(base,{"scanner_runs":[{"scanner":"gitleaks","status":"COMPLETE"}]}) == "REVIEW" }
test_active_exception_suppresses_review if {
  security_gate.result.decision with input as object.union(base,{
    "findings":[{"finding_id":"CVE-1","category":"vulnerability","confidence":"HIGH","severity":"HIGH"}],
    "exceptions":[{"finding_id":"CVE-1","scope":"t","expires_at":"2026-09-25T00:00:00Z"}]
  }) == "ALLOW"
}

test_partial_finding_requires_review if {
  security_gate.result.decision with input as object.union(base,{
    "findings":[{"finding_id":"partial","category":"vulnerability","confidence":"LOW","severity":"LOW","scan_status":"PARTIAL"}]
  }) == "REVIEW"
}

test_active_exception_suppresses_critical_misconfiguration if {
  security_gate.result.decision with input as object.union(base,{
    "findings":[{"finding_id":"MISCONFIG-1","category":"misconfiguration","confidence":"HIGH","severity":"CRITICAL","scan_status":"COMPLETE"}],
    "exceptions":[{"finding_id":"MISCONFIG-1","scope":"t","expires_at":"2026-09-25T00:00:00Z"}]
  }) == "ALLOW"
}
