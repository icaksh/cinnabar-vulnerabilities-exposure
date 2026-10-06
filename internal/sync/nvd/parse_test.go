package nvd

import (
	"encoding/json"
	"testing"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

func parseFixture(t *testing.T, raw string) []model.Vulnerability {
	t.Helper()
	vuls, _ := parseWithConfigs(t, raw)
	return vuls
}

func parseWithConfigs(t *testing.T, raw string) ([]model.Vulnerability, []model.Configuration) {
	t.Helper()
	var resp Response
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return Parse(resp)
}

func flattenMatches(cfgs []model.Configuration) []model.CPEMatch {
	var out []model.CPEMatch
	for _, c := range cfgs {
		for _, n := range c.Nodes {
			out = append(out, n.Matches...)
		}
	}
	return out
}

func TestParseBasic(t *testing.T) {
	raw := `{
		"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
		"vulnerabilities": [
			{"cve": {
				"id": "CVE-2020-0001",
				"published": "2020-01-01T10:00:00.000",
				"lastModified": "2021-01-01T10:00:00.000",
				"descriptions": [
					{"lang": "en", "value": "An English description."},
					{"lang": "fr", "value": "Une description."}
				],
				"metrics": {
					"cvssMetricV31": [{"cvssData": {
						"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						"baseScore": 9.8, "baseSeverity": "CRITICAL"
					}}]
				},
				"weaknesses": [
					{"description": [{"lang": "en", "value": "CWE-79"}]},
					{"description": [{"lang": "en", "value": "CWE-79"}]}
				],
				"configurations": [
					{"nodes": [{"cpeMatch": [
						{"vulnerable": true, "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "AAA",
						 "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
					]}]}
				],
				"references": [{"url": "https://example.com", "source": "vendor", "tags": ["Patch"]}]
			}}
		]
	}`
	vuls := parseFixture(t, raw)
	if len(vuls) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vuls))
	}
	v := vuls[0]
	if v.CVEID != "CVE-2020-0001" {
		t.Fatalf("cve id = %v", v.CVEID)
	}
	if v.Description != "An English description." {
		t.Fatalf("description = %v", v.Description)
	}
	if v.Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", v.Severity)
	}
	if v.CVSSScore == nil || *v.CVSSScore != 9.8 {
		t.Fatalf("score = %v", v.CVSSScore)
	}
	if v.CVSSVersion == nil || *v.CVSSVersion != "3.1" {
		t.Fatalf("version = %v", v.CVSSVersion)
	}
	if len(v.CWEIDs) != 1 || v.CWEIDs[0] != "CWE-79" {
		t.Fatalf("cwes = %v", v.CWEIDs)
	}
	if len(v.References) != 1 || v.References[0].URL != "https://example.com" {
		t.Fatalf("references = %v", v.References)
	}
}

func TestMissingCVSS(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0002",
		"descriptions": [{"lang": "en", "value": "No metrics."}]
	}}]}`
	vuls := parseFixture(t, raw)
	v := vuls[0]
	if v.Severity != model.SeverityUnknown {
		t.Fatalf("severity = %v, want UNKNOWN", v.Severity)
	}
	if v.CVSSScore != nil {
		t.Fatalf("score should be nil, got %v", *v.CVSSScore)
	}
}

func TestCVSSPreferenceV4(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0003",
		"metrics": {
			"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 9.0, "vectorString": "CVSS:4.0/..."}}],
			"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 8.0, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/..."}}]
		}
	}}]}`
	vuls := parseFixture(t, raw)
	v := vuls[0]
	if v.CVSSVersion == nil || *v.CVSSVersion != "4.0" {
		t.Fatalf("version = %v, want 4.0", v.CVSSVersion)
	}
	if *v.CVSSScore != 9.0 {
		t.Fatalf("score = %v, want 9.0", *v.CVSSScore)
	}
	if v.Severity != model.SeverityCritical {
		t.Fatalf("severity = %v, want CRITICAL (derived from 9.0)", v.Severity)
	}
}

func TestCPEBoundariesPreserved(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0004",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": true, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "matchCriteriaId": "B1",
			 "versionStartIncluding": "1.2.0", "versionEndExcluding": "1.4.0"}
		]}]}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	matches := flattenMatches(cfgs)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Part != "a" || m.Vendor != "vendor" || m.Product != "product" {
		t.Fatalf("parsed cpe wrong: %+v", m)
	}
	if m.VersionStartIncl == nil || *m.VersionStartIncl != "1.2.0" {
		t.Fatalf("start incl = %v", m.VersionStartIncl)
	}
	if m.VersionEndExcl == nil || *m.VersionEndExcl != "1.4.0" {
		t.Fatalf("end excl = %v", m.VersionEndExcl)
	}
	if m.VersionStartExcl != nil || m.VersionEndIncl != nil {
		t.Fatalf("unexpected boundaries: %+v", m)
	}
}

func TestMissingOptionalFields(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {"id": "CVE-2020-0005"}}]}`
	vuls := parseFixture(t, raw)
	if len(vuls) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vuls))
	}
	v := vuls[0]
	if v.CVEID != "CVE-2020-0005" {
		t.Fatalf("cve id = %v", v.CVEID)
	}
	if v.Severity != model.SeverityUnknown {
		t.Fatalf("severity = %v", v.Severity)
	}
	if v.CWEIDs == nil || v.References == nil {
		t.Fatalf("expected non-nil slices")
	}
}

func TestExclusiveStartBoundary(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0006",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionStartExcluding": "2.0", "versionEndIncluding": "3.0"}
		]}]}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	m := flattenMatches(cfgs)[0]
	if m.VersionStartExcl == nil || *m.VersionStartExcl != "2.0" {
		t.Fatalf("start excl = %v", m.VersionStartExcl)
	}
	if m.VersionEndIncl == nil || *m.VersionEndIncl != "3.0" {
		t.Fatalf("end incl = %v", m.VersionEndIncl)
	}
}

func TestConfigurationTreePreserved(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0007",
		"configurations": [{
			"operator": "AND",
			"negate": false,
			"nodes": [
				{"operator": "OR", "negate": false, "cpeMatch": [
					{"vulnerable": true, "criteria": "cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", "matchCriteriaId": "M1"}
				]},
				{"operator": "OR", "negate": true, "cpeMatch": [
					{"vulnerable": false, "criteria": "cpe:2.3:o:acme:os:*:*:*:*:*:*:*:*", "matchCriteriaId": "M2"}
				]}
			]
		}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 configuration, got %d", len(cfgs))
	}
	c := cfgs[0]
	if c.CVEID != "CVE-2020-0007" || c.Operator != "AND" || c.Negate {
		t.Fatalf("configuration wrong: %+v", c)
	}
	if len(c.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(c.Nodes))
	}
	if c.Nodes[0].Operator != "OR" || c.Nodes[0].Negate {
		t.Fatalf("node 0 wrong: %+v", c.Nodes[0])
	}
	if c.Nodes[1].Operator != "OR" || !c.Nodes[1].Negate {
		t.Fatalf("node 1 negate not preserved: %+v", c.Nodes[1])
	}
	if c.Nodes[1].Matches[0].Vulnerable {
		t.Fatalf("vulnerable=false not preserved: %+v", c.Nodes[1].Matches[0])
	}
}

func TestVulnerableFalsePreserved(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0008",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*", "matchCriteriaId": "ENV1"}
		]}]}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	m := flattenMatches(cfgs)[0]
	if m.Vulnerable {
		t.Fatalf("vulnerable flag not preserved: %+v", m)
	}
	if m.Part != "o" || m.Vendor != "microsoft" || m.Product != "windows_10" {
		t.Fatalf("components wrong: %+v", m)
	}
}

func TestDuplicateCriteriaDifferentRangesBothKept(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0009",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"},
			{"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "4.0"}
		]}]}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	matches := flattenMatches(cfgs)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (different ranges), got %d", len(matches))
	}
	if matches[0].MatchCriteriaID == matches[1].MatchCriteriaID {
		t.Fatalf("rules with different ranges must not share identity: %s", matches[0].MatchCriteriaID)
	}
}

func TestDuplicateCriteriaAcrossConfigsPreserved(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0010",
		"configurations": [
			{"nodes": [{"cpeMatch": [
				{"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0", "matchCriteriaId": "D1"}
			]}]},
			{"nodes": [{"cpeMatch": [
				{"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0", "matchCriteriaId": "D1"}
			]}]}
		]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 configurations preserved, got %d", len(cfgs))
	}
	if len(flattenMatches(cfgs)) != 2 {
		t.Fatalf("expected the same criteria in both configs to survive, got %d", len(flattenMatches(cfgs)))
	}
}

func TestFullCPEComponentsPreserved(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0011",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": true, "criteria": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x64:*", "matchCriteriaId": "F1"}
		]}]}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	m := flattenMatches(cfgs)[0]
	if m.Version != "-" || m.TargetHW != "x64" || m.TargetSW != "*" {
		t.Fatalf("full components wrong: %+v", m)
	}
	if m.Update != "*" || m.Edition != "*" || m.Language != "*" {
		t.Fatalf("wildcard components wrong: %+v", m)
	}
}

func TestOperatorDefaults(t *testing.T) {
	raw := `{"vulnerabilities": [{"cve": {
		"id": "CVE-2020-0012",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "matchCriteriaId": "O1"}
		]}]}]
	}}]}`
	_, cfgs := parseWithConfigs(t, raw)
	if cfgs[0].Operator != "OR" {
		t.Fatalf("configuration default operator = %q, want OR", cfgs[0].Operator)
	}
	if cfgs[0].Nodes[0].Operator != "OR" {
		t.Fatalf("node default operator = %q, want OR", cfgs[0].Nodes[0].Operator)
	}
}