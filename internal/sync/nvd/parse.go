package nvd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/cpe"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type QueryParams struct {
	LastModStartDate *time.Time
	LastModEndDate   *time.Time
}

type Response struct {
	ResultsPerPage  int                  `json:"resultsPerPage"`
	StartIndex      int                  `json:"startIndex"`
	TotalResults    int                  `json:"totalResults"`
	Vulnerabilities []VulnerabilityEntry `json:"vulnerabilities"`
}

type VulnerabilityEntry struct {
	CVE cveRecord `json:"cve"`
}

type cveRecord struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []description   `json:"descriptions"`
	Metrics        metrics         `json:"metrics"`
	Weaknesses     []weakness      `json:"weaknesses"`
	Configurations []configuration `json:"configurations"`
	References     []reference     `json:"references"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CVSSMetricV40 []cvssMetricV40 `json:"cvssMetricV40"`
	CVSSMetricV31 []cvssMetricV31 `json:"cvssMetricV31"`
	CVSSMetricV30 []cvssMetricV30 `json:"cvssMetricV30"`
	CVSSMetricV2  []cvssMetricV2  `json:"cvssMetricV2"`
}

type cvssMetricV40 struct {
	CVSSData cvssV40Data `json:"cvssData"`
}

type cvssV40Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cvssMetricV31 struct {
	CVSSData cvssV3Data `json:"cvssData"`
}

type cvssMetricV30 struct {
	CVSSData cvssV3Data `json:"cvssData"`
}

type cvssV3Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cvssMetricV2 struct {
	BaseSeverity string     `json:"baseSeverity"`
	CVSSData     cvssV2Data `json:"cvssData"`
}

type cvssV2Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []description `json:"description"`
}

type configuration struct {
	Operator string `json:"operator"`
	Negate   bool   `json:"negate"`
	Nodes    []node `json:"nodes"`
}

type node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

func Parse(resp Response) ([]model.Vulnerability, []model.Configuration) {
	vuls := make([]model.Vulnerability, 0, len(resp.Vulnerabilities))
	var configs []model.Configuration
	for _, entry := range resp.Vulnerabilities {
		v, cfgs := parseRecord(entry.CVE)
		if v.CVEID == "" {
			continue
		}
		vuls = append(vuls, v)
		configs = append(configs, cfgs...)
	}
	return vuls, configs
}

func parseRecord(r cveRecord) (model.Vulnerability, []model.Configuration) {
	v := model.Vulnerability{
		CVEID:       r.ID,
		Description: englishDescription(r.Descriptions),
		PublishedAt: parseTime(r.Published),
		ModifiedAt:  parseTime(r.LastModified),
		CWEIDs:      extractCWEs(r.Weaknesses),
		References:  parseReferences(r.References),
	}
	if v.CWEIDs == nil {
		v.CWEIDs = []string{}
	}
	if v.References == nil {
		v.References = []model.Reference{}
	}

	version, score, severity, vector := selectCVSS(r.Metrics)
	if score != nil {
		v.CVSSVersion = &version
		v.CVSSScore = score
		v.Severity = model.Severity(normalizeSeverity(severity))
		v.CVSSVector = strPtr(vector)
	} else {
		v.Severity = model.SeverityUnknown
	}

	return v, parseConfigurations(r.ID, r.Configurations)
}

// parseConfigurations preserves the NVD applicability expression: each
// configuration keeps its operator/negate and its nodes; each node keeps its
// operator/negate and its CPE match list. Nodes are not flattened away.
func parseConfigurations(cveID string, cfgs []configuration) []model.Configuration {
	out := make([]model.Configuration, 0, len(cfgs))
	for i, cfg := range cfgs {
		if len(cfg.Nodes) == 0 {
			continue
		}
		c := model.Configuration{
			CVEID:    cveID,
			Operator: defaultOperator(cfg.Operator, "OR"),
			Negate:   cfg.Negate,
			Position: i,
		}
		for j, nd := range cfg.Nodes {
			if len(nd.CPEMatch) == 0 {
				continue
			}
			n := model.ConfigurationNode{
				Operator: defaultOperator(nd.Operator, "OR"),
				Negate:   nd.Negate,
				Position: j,
			}
			seen := make(map[string]bool, len(nd.CPEMatch))
			for _, cm := range nd.CPEMatch {
				m := buildCPEMatch(cveID, cm)
				if seen[m.MatchCriteriaID] {
					continue
				}
				seen[m.MatchCriteriaID] = true
				n.Matches = append(n.Matches, m)
			}
			c.Nodes = append(c.Nodes, n)
		}
		if len(c.Nodes) > 0 {
			out = append(out, c)
		}
	}
	return out
}

func defaultOperator(op, fallback string) string {
	op = strings.TrimSpace(strings.ToUpper(op))
	switch op {
	case "AND", "OR":
		return op
	default:
		return fallback
	}
}

func selectCVSS(m metrics) (string, *float64, string, string) {
	if len(m.CVSSMetricV40) > 0 {
		d := m.CVSSMetricV40[0].CVSSData
		s := d.BaseScore
		return "4.0", &s, severityFromV3(s, d.BaseSeverity), d.VectorString
	}
	if len(m.CVSSMetricV31) > 0 {
		d := m.CVSSMetricV31[0].CVSSData
		s := d.BaseScore
		return "3.1", &s, severityFromV3(s, d.BaseSeverity), d.VectorString
	}
	if len(m.CVSSMetricV30) > 0 {
		d := m.CVSSMetricV30[0].CVSSData
		s := d.BaseScore
		return "3.0", &s, severityFromV3(s, d.BaseSeverity), d.VectorString
	}
	if len(m.CVSSMetricV2) > 0 {
		d := m.CVSSMetricV2[0]
		s := d.CVSSData.BaseScore
		return "2.0", &s, severityFromV2(s, d.BaseSeverity), d.CVSSData.VectorString
	}
	return "", nil, "", ""
}

func severityFromV3(score float64, provided string) string {
	if provided != "" && !strings.EqualFold(provided, "NOT_DEFINED") {
		return provided
	}
	switch {
	case score <= 0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func severityFromV2(score float64, provided string) string {
	if provided != "" && !strings.EqualFold(provided, "NOT_DEFINED") {
		return provided
	}
	switch {
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	default:
		return "HIGH"
	}
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return strings.ToUpper(s)
	default:
		return "UNKNOWN"
	}
}

func englishDescription(descs []description) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}

func extractCWEs(weaknesses []weakness) []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range weaknesses {
		for _, d := range w.Description {
			v := strings.TrimSpace(d.Value)
			if v == "" {
				continue
			}
			if strings.HasPrefix(v, "CWE-") && !strings.HasPrefix(v, "NVD-CWE") {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
		}
	}
	return out
}

func parseReferences(refs []reference) []model.Reference {
	out := make([]model.Reference, 0, len(refs))
	for _, r := range refs {
		out = append(out, model.Reference{URL: r.URL, Source: r.Source, Tags: r.Tags})
	}
	return out
}

func buildCPEMatch(cveID string, cm cpeMatch) model.CPEMatch {
	m := model.CPEMatch{
		CVEID:            cveID,
		MatchCriteriaID:  cm.MatchCriteriaID,
		Criteria:         cm.Criteria,
		Vulnerable:       cm.Vulnerable,
		VersionStartIncl: strPtr(cm.VersionStartIncluding),
		VersionStartExcl: strPtr(cm.VersionStartExcluding),
		VersionEndIncl:   strPtr(cm.VersionEndIncluding),
		VersionEndExcl:   strPtr(cm.VersionEndExcluding),
	}
	if c, err := cpe.Parse(cm.Criteria); err == nil {
		m.Part = c.PartLower()
		m.Vendor = c.VendorLower()
		m.Product = c.ProductLower()
		m.Version = c.Version
		m.Update = c.Update
		m.Edition = c.Edition
		m.Language = c.Language
		m.SWEdition = c.SWEdition
		m.TargetSW = c.TargetSW
		m.TargetHW = c.TargetHW
		m.Other = c.Other
	}
	if m.MatchCriteriaID == "" {
		m.MatchCriteriaID = syntheticMatchID(m)
	}
	return m
}

// syntheticMatchID provides a stable fallback identity when NVD omits
// matchCriteriaId, so rules that differ only by range or context are not
// silently merged.
func syntheticMatchID(m model.CPEMatch) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s",
		m.Criteria,
		strVal(m.VersionStartIncl), strVal(m.VersionStartExcl),
		strVal(m.VersionEndIncl), strVal(m.VersionEndExcl))
	return "gen-" + hex.EncodeToString(h.Sum(nil)[:16])
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
