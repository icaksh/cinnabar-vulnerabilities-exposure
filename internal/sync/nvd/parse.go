package nvd

import (
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

func Parse(resp Response) ([]model.Vulnerability, []model.CPEMatch) {
	vuls := make([]model.Vulnerability, 0, len(resp.Vulnerabilities))
	var matches []model.CPEMatch
	for _, entry := range resp.Vulnerabilities {
		v, ms := parseRecord(entry.CVE)
		if v.CVEID == "" {
			continue
		}
		vuls = append(vuls, v)
		matches = append(matches, ms...)
	}
	return vuls, matches
}

func parseRecord(r cveRecord) (model.Vulnerability, []model.CPEMatch) {
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

	var matches []model.CPEMatch
	seen := make(map[string]bool)
	for _, cfg := range r.Configurations {
		for _, nd := range cfg.Nodes {
			for _, cm := range nd.CPEMatch {
				m := buildCPEMatch(r.ID, cm)
				if seen[m.Criteria] {
					continue
				}
				seen[m.Criteria] = true
				matches = append(matches, m)
			}
		}
	}
	return v, matches
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
	}
	return m
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
