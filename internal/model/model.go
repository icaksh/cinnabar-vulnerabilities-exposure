package model

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityNone     Severity = "NONE"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Vulnerability struct {
	ID          int64  `json:"-"`
	CVEID       string `json:"cve_id"`
	Description string `json:"description"`

	PublishedAt *time.Time `json:"published_at,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`

	CVSSVersion *string  `json:"cvss_version,omitempty"`
	CVSSScore   *float64 `json:"cvss,omitempty"`
	Severity    Severity `json:"severity"`
	CVSSVector  *string  `json:"cvss_vector,omitempty"`

	CWEIDs     []string    `json:"cwe_ids"`
	References []Reference `json:"references"`

	IsKEV                         bool       `json:"is_kev"`
	KEVDateAdded                  *time.Time `json:"kev_date_added,omitempty"`
	KEVDueDate                    *time.Time `json:"kev_due_date,omitempty"`
	KEVRequiredAction             *string    `json:"kev_required_action,omitempty"`
	KEVKnownRansomwareCampaignUse bool       `json:"kev_known_ransomware_campaign_use"`

	SourceUpdatedAt *time.Time `json:"-"`
	CreatedAt       time.Time  `json:"-"`
	UpdatedAt       time.Time  `json:"-"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

type CPEMatch struct {
	ID               int64     `json:"-"`
	CVEID            string    `json:"cve_id"`
	MatchCriteriaID  string    `json:"match_criteria_id,omitempty"`
	Criteria         string    `json:"criteria"`
	Part             string    `json:"part"`
	Vendor           string    `json:"vendor"`
	Product          string    `json:"product"`
	Version          string    `json:"version,omitempty"`
	VersionStartIncl *string   `json:"version_start_including,omitempty"`
	VersionStartExcl *string   `json:"version_start_excluding,omitempty"`
	VersionEndIncl   *string   `json:"version_end_including,omitempty"`
	VersionEndExcl   *string   `json:"version_end_excluding,omitempty"`
	Vulnerable       bool      `json:"vulnerable"`
	CreatedAt        time.Time `json:"-"`
	UpdatedAt        time.Time `json:"-"`
}

type SyncState struct {
	Source           string     `json:"source"`
	Status           string     `json:"status"`
	LastAttemptAt    *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt    *time.Time `json:"last_success_at,omitempty"`
	LastError        *string    `json:"last_error,omitempty"`
	RecordsProcessed int64      `json:"records_processed"`
	SyncCursor       *time.Time `json:"sync_cursor,omitempty"`
	CreatedAt        time.Time  `json:"-"`
	UpdatedAt        time.Time  `json:"-"`
}

type PendingKEV struct {
	CVEID                      string
	DateAdded                  *time.Time
	DueDate                    *time.Time
	RequiredAction             *string
	KnownRansomwareCampaignUse bool
	Raw                        json.RawMessage
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

type ResolveRequest struct {
	CPEs       []string `json:"cpes"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Method     string   `json:"method"`
	Confidence int      `json:"confidence"`
}

type BatchResolveRequest struct {
	Items []BatchResolveItem `json:"items"`
}

type BatchResolveItem struct {
	ClientRef  string   `json:"client_ref"`
	CPEs       []string `json:"cpes"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Method     string   `json:"method"`
	Confidence int      `json:"confidence"`
}

type MatchState string

const (
	StateMatched          MatchState = "MATCHED"
	StateNotMatched       MatchState = "NOT_MATCHED"
	StateUncertain        MatchState = "UNCERTAIN"
	StateInsufficientData MatchState = "INSUFFICIENT_DATA"
)

type MatchConfidence string

const (
	ConfidenceHigh   MatchConfidence = "HIGH"
	ConfidenceMedium MatchConfidence = "MEDIUM"
	ConfidenceLow    MatchConfidence = "LOW"
)

type Match struct {
	CVEID           string          `json:"cve_id"`
	State           MatchState      `json:"state"`
	Severity        Severity        `json:"severity"`
	CVSS            *float64        `json:"cvss,omitempty"`
	IsKEV           bool            `json:"is_kev"`
	MatchedInputCPE string          `json:"matched_input_cpe,omitempty"`
	MatchedCriteria string          `json:"matched_criteria,omitempty"`
	Version         string          `json:"version,omitempty"`
	MatchConfidence MatchConfidence `json:"match_confidence,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	Description     string          `json:"-"`
}

type BatchResolution struct {
	Results []BatchResolutionItem `json:"results"`
}

type BatchResolutionItem struct {
	ClientRef string  `json:"client_ref"`
	Status    string  `json:"status"`
	Matches   []Match `json:"matches"`
	Uncertain []Match `json:"uncertain"`
}
