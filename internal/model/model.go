package model

import "time"

type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

type ScanStatus string

const (
	StatusComplete    ScanStatus = "COMPLETE"
	StatusPartial     ScanStatus = "PARTIAL"
	StatusFailed      ScanStatus = "FAILED"
	StatusTimeout     ScanStatus = "TIMEOUT"
	StatusUnsupported ScanStatus = "UNSUPPORTED"
)

type Decision string

const (
	DecisionAllow  Decision = "ALLOW"
	DecisionReview Decision = "REVIEW"
	DecisionBlock  Decision = "BLOCK"
	DecisionError  Decision = "ERROR"
)

type Finding struct {
	SchemaVersion         string         `json:"schema_version"`
	Scanner               string         `json:"scanner"`
	ScannerVersion        string         `json:"scanner_version"`
	ScannerArtifactDigest string         `json:"scanner_artifact_digest"`
	TargetID              string         `json:"target_id"`
	Category              string         `json:"category"`
	FindingID             string         `json:"finding_id"`
	Severity              Severity       `json:"severity"`
	Confidence            Confidence     `json:"confidence"`
	Title                 string         `json:"title"`
	Description           string         `json:"description,omitempty"`
	Component             string         `json:"component,omitempty"`
	InstalledVersion      string         `json:"installed_version,omitempty"`
	FixedVersion          string         `json:"fixed_version,omitempty"`
	Exploitability        string         `json:"exploitability,omitempty"`
	Evidence              map[string]any `json:"evidence,omitempty"`
	References            []string       `json:"references,omitempty"`
	Remediation           string         `json:"remediation,omitempty"`
	ScanStatus            ScanStatus     `json:"scan_status"`
}

type ScannerRun struct {
	Scanner           string     `json:"scanner"`
	Version           string     `json:"version"`
	ArtifactDigest    string     `json:"artifact_digest"`
	DBVersion         string     `json:"db_version,omitempty"`
	DBUpdatedAt       *time.Time `json:"db_updated_at,omitempty"`
	AdvisoryCheckedAt *time.Time `json:"advisory_checked_at,omitempty"`
	Status            ScanStatus `json:"status"`
	StartedAt         time.Time  `json:"started_at"`
	FinishedAt        time.Time  `json:"finished_at"`
	ErrorCode         string     `json:"error_code,omitempty"`
	Message           string     `json:"message,omitempty"`
}

type Exception struct {
	FindingID     string         `json:"finding_id"`
	Justification string         `json:"justification"`
	Approver      string         `json:"approver"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Scope         string         `json:"scope"`
	Evidence      map[string]any `json:"evidence"`
}

type PolicyInput struct {
	SchemaVersion string         `json:"schema_version"`
	Now           time.Time      `json:"now"`
	TargetID      string         `json:"target_id"`
	Findings      []Finding      `json:"findings"`
	ScannerRuns   []ScannerRun   `json:"scanner_runs"`
	Exceptions    []Exception    `json:"exceptions"`
	PolicyVersion string         `json:"policy_version"`
	Policy        PolicySettings `json:"policy"`
}

type PolicySettings struct {
	VulnerabilityDBMaxAgeHours int  `json:"vulnerability_db_max_age_hours"`
	AdvisoryReviewMaxAgeDays   int  `json:"advisory_review_max_age_days"`
	ScorecardReviewBelow       int  `json:"scorecard_review_below"`
	ExceptionsRequireExpiry    bool `json:"exceptions_require_expiry"`
	FailClosed                 bool `json:"fail_closed"`
}

type PolicyDecision struct {
	Decision Decision `json:"decision"`
	Reasons  []string `json:"reasons"`
}

type Report struct {
	SchemaVersion  string         `json:"schema_version"`
	ScanID         string         `json:"scan_id"`
	TargetID       string         `json:"target_id"`
	TargetType     string         `json:"target_type"`
	GeneratedAt    time.Time      `json:"generated_at"`
	PolicyVersion  string         `json:"policy_version"`
	Decision       Decision       `json:"decision"`
	Reasons        []string       `json:"reasons"`
	ScannerRuns    []ScannerRun   `json:"scanner_runs"`
	Findings       []Finding      `json:"findings"`
	ExceptionsUsed []Exception    `json:"exceptions_used,omitempty"`
	ResultHash     string         `json:"result_hash"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}
