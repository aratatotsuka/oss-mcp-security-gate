package security_gate

import rego.v1

error_reasons contains sprintf("%s failed", [r.scanner]) if {
  some r in input.scanner_runs
  r.status == "FAILED"
}

error_reasons contains sprintf("%s timeout", [r.scanner]) if {
  some r in input.scanner_runs
  r.status == "TIMEOUT"
}

error_reasons contains sprintf("%s integrity verification prevented scan", [r.scanner]) if {
  some r in input.scanner_runs
  contains(r.error_code, "INTEGRITY")
}

error_reasons contains "no scanner result" if { count(input.scanner_runs) == 0 }

block_reasons contains sprintf("%s: confirmed secret exposure", [f.finding_id]) if {
  some f in input.findings
  f.category == "secret"
  f.confidence == "HIGH"
}

block_reasons contains sprintf("%s: security invariant violation", [f.finding_id]) if {
  some f in input.findings
  f.category in {"integrity", "prohibited-capability"}
}

block_reasons contains sprintf("%s: malicious MCP YARA finding", [f.finding_id]) if {
  some f in input.findings
  f.category == "mcp"
  contains(upper(f.finding_id), "YARA")
}

block_reasons contains sprintf("%s: critical misconfiguration", [f.finding_id]) if {
  some f in input.findings
  f.category == "misconfiguration"
  f.severity == "CRITICAL"
  not ignored(f)
}

active_exception(f) if {
  some e in input.exceptions
  e.finding_id == f.finding_id
  e.scope in {"*", input.target_id}
  time.parse_rfc3339_ns(e.expires_at) > time.parse_rfc3339_ns(input.now)
}

overridable(f) if {
  f.category != "integrity"
  f.category != "secret"
  f.category != "prohibited-capability"
  f.category != "mcp"
}

overridable(f) if {
  f.category == "mcp"
  not contains(upper(f.finding_id), "YARA")
}

policy_config := object.get(input, "policy", {})
db_max_age_ns := object.get(policy_config, "vulnerability_db_max_age_hours", 72) * 3600000000000
advisory_max_age_ns := object.get(policy_config, "advisory_review_max_age_days", 30) * 86400000000000

review_reasons contains sprintf("%s scan incomplete: %s", [r.scanner, r.status]) if {
  some r in input.scanner_runs
  r.status in {"PARTIAL", "UNSUPPORTED"}
}

review_reasons contains sprintf("%s vulnerability DB is stale", [r.scanner]) if {
  some r in input.scanner_runs
  r.db_updated_at
  time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(r.db_updated_at) > db_max_age_ns
}

review_reasons contains sprintf("%s security advisory review is stale", [r.scanner]) if {
  some r in input.scanner_runs
  r.advisory_checked_at
  time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(r.advisory_checked_at) > advisory_max_age_ns
}

review_reasons contains sprintf("%s security advisory review is missing", [r.scanner]) if {
  some r in input.scanner_runs
  not r.advisory_checked_at
}

review_reasons contains sprintf("%s: high severity finding", [f.finding_id]) if {
  some f in input.findings
  f.severity in {"HIGH", "CRITICAL"}
  not block_finding(f)
  not ignored(f)
}

review_reasons contains sprintf("%s: unknown severity", [f.finding_id]) if {
  some f in input.findings
  f.severity == "UNKNOWN"
  not ignored(f)
}

review_reasons contains sprintf("%s: incomplete finding status", [f.finding_id]) if {
  some f in input.findings
  f.scan_status != "COMPLETE"
  not ignored(f)
}

block_finding(f) if { f.category in {"integrity", "prohibited-capability"} }
block_finding(f) if { f.category == "secret"; f.confidence == "HIGH" }
block_finding(f) if { f.category == "mcp"; contains(upper(f.finding_id), "YARA") }
block_finding(f) if { f.category == "misconfiguration"; f.severity == "CRITICAL" }

ignored(f) if { overridable(f); active_exception(f) }

decision := "ERROR" if { count(error_reasons) > 0
} else := "BLOCK" if { count(block_reasons) > 0
} else := "REVIEW" if { count(review_reasons) > 0
} else := "ALLOW"

reasons := sort(union({error_reasons, block_reasons, review_reasons}))
result := {"decision": decision, "reasons": reasons}
