package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/cpe"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type fakeStore struct {
	candidateCVEs map[string][]string
	cfgs          map[string][]model.Configuration
	legacy        map[string][]model.CPEMatch
	vulns         map[string]model.Vulnerability
}

func (f *fakeStore) CandidateCVEs(_ context.Context, _ string, vendor, product string) ([]string, error) {
	return f.candidateCVEs[vendor+"|"+product], nil
}
func (f *fakeStore) GetConfigurations(_ context.Context, _ []string) (map[string][]model.Configuration, error) {
	return f.cfgs, nil
}
func (f *fakeStore) GetLegacyMatches(_ context.Context, _ []string) (map[string][]model.CPEMatch, error) {
	return f.legacy, nil
}
func (f *fakeStore) GetVulnerabilitiesByIDs(_ context.Context, ids []string) (map[string]model.Vulnerability, error) {
	out := map[string]model.Vulnerability{}
	for _, id := range ids {
		if v, ok := f.vulns[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

func newStore() *fakeStore {
	return &fakeStore{
		candidateCVEs: map[string][]string{},
		cfgs:          map[string][]model.Configuration{},
		legacy:        map[string][]model.CPEMatch{},
		vulns:         map[string]model.Vulnerability{},
	}
}

func sp(s string) *string { return &s }
func fp(f float64) *float64 { return &f }

// match parses a criteria string like the NVD parser does and populates all
// CPE components, so tests reflect real production data.
func match(cveID, criteria string, vuln bool) model.CPEMatch {
	c, err := cpe.Parse(criteria)
	if err != nil {
		panic(err)
	}
	return model.CPEMatch{
		CVEID:           cveID,
		MatchCriteriaID: "m-" + criteria,
		Criteria:        criteria,
		Part:            c.PartLower(),
		Vendor:          c.VendorLower(),
		Product:         c.ProductLower(),
		Version:         c.Version,
		Update:          c.Update,
		Edition:         c.Edition,
		Language:        c.Language,
		SWEdition:       c.SWEdition,
		TargetSW:        c.TargetSW,
		TargetHW:        c.TargetHW,
		Other:           c.Other,
		Vulnerable:      vuln,
	}
}

func rangedMatch(cveID, criteria string, vuln bool, startIncl, startExcl, endIncl, endExcl *string) model.CPEMatch {
	m := match(cveID, criteria, vuln)
	m.VersionStartIncl = startIncl
	m.VersionStartExcl = startExcl
	m.VersionEndIncl = endIncl
	m.VersionEndExcl = endExcl
	return m
}

func node(operator string, negate bool, ms ...model.CPEMatch) model.ConfigurationNode {
	return model.ConfigurationNode{Operator: operator, Negate: negate, Matches: ms}
}

func config(cveID, operator string, negate bool, ns ...model.ConfigurationNode) model.Configuration {
	return model.Configuration{CVEID: cveID, Operator: operator, Negate: negate, Nodes: ns}
}

func resolveWith(t *testing.T, s *fakeStore, cpes []string, version string) *Result {
	t.Helper()
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{
		CPEs: cpes, Product: "", Version: version, Method: "probed", Confidence: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func findState(res *Result, cveID string) model.MatchState {
	for _, m := range res.Matches {
		if m.CVEID == cveID {
			return m.State
		}
	}
	for _, m := range res.Uncertain {
		if m.CVEID == cveID {
			return m.State
		}
	}
	for _, m := range res.NotMatched {
		if m.CVEID == cveID {
			return m.State
		}
	}
	return ""
}

func oneRuleStore(m model.CPEMatch) *fakeStore {
	s := newStore()
	s.candidateCVEs[m.Vendor+"|"+m.Product] = []string{m.CVEID}
	s.cfgs[m.CVEID] = []model.Configuration{
		config(m.CVEID, "OR", false, node("OR", false, m)),
	}
	return s
}

func TestBoundaryRange(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-2020-0001", "cpe:2.3:a:test:pkg:*:*:*:*:*:*:*:*", true, sp("1.2.0"), nil, nil, sp("1.4.0")))
	cases := []struct {
		version string
		want    model.MatchState
	}{
		{"1.1.9", model.StateNotMatched},
		{"1.2.0", model.StateMatched},
		{"1.3.9", model.StateMatched},
		{"1.4.0", model.StateNotMatched},
	}
	for _, c := range cases {
		res := resolveWith(t, s, []string{"cpe:/a:test:pkg:" + c.version}, c.version)
		if got := findState(res, "CVE-2020-0001"); got != c.want {
			t.Errorf("version %s: state = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestInclusiveExclusiveBoundaries(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, sp("1.0"), nil, sp("2.0"), nil))
	check := func(v string, want model.MatchState) {
		res := resolveWith(t, s, []string{"cpe:/a:v:p:" + v}, v)
		if got := findState(res, "CVE-1"); got != want {
			t.Errorf("version %s: state = %v, want %v", v, got, want)
		}
	}
	check("0.9", model.StateNotMatched)
	check("1.0", model.StateMatched)
	check("2.0", model.StateMatched)
	check("2.1", model.StateNotMatched)
}

func TestDifferentVendorProduct(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", true))
	res := resolveWith(t, s, []string{"cpe:/a:other:thing:1.0"}, "1.0")
	if len(res.Matches) != 0 || len(res.Uncertain) != 0 {
		t.Fatalf("expected no matches, got %+v", res)
	}
}

func TestMissingVersionUnbounded(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true))
	res := resolveWith(t, s, []string{"cpe:/a:v:p"}, "")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestMissingVersionBounded(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, sp("1.0"), nil, nil, nil))
	res := resolveWith(t, s, []string{"cpe:/a:v:p"}, "")
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN", got)
	}
}

func TestUncomparableVersion(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, nil, nil, sp("1.0"), nil))
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.0u1"}, "1.0u1")
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN", got)
	}
}

func TestOpenSSH(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-2024-6387", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", true, sp("9.0"), nil, nil, sp("9.7")))
	s.vulns["CVE-2024-6387"] = model.Vulnerability{CVEID: "CVE-2024-6387", Severity: model.SeverityHigh, CVSSScore: fp(8.1), IsKEV: true}

	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{
		CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}, Product: "OpenSSH", Version: "9.6p1", Method: "probed", Confidence: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", res)
	}
	m := res.Matches[0]
	if m.CVEID != "CVE-2024-6387" || m.State != model.StateMatched || m.Severity != model.SeverityHigh || !m.IsKEV {
		t.Fatalf("unexpected match: %+v", m)
	}
	if m.MatchConfidence != model.ConfidenceHigh {
		t.Fatalf("confidence = %v, want HIGH", m.MatchConfidence)
	}
	if m.MatchedInputCPE != "cpe:/a:openbsd:openssh:9.6p1" {
		t.Fatalf("matched input cpe = %v", m.MatchedInputCPE)
	}
}

func TestMultipleCPEAndDedup(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|one"] = []string{"CVE-1"}
	s.candidateCVEs["v|two"] = []string{"CVE-2", "CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false, node("OR", false, match("CVE-1", "cpe:2.3:a:v:one:*:*:*:*:*:*:*:*", true)))}
	s.cfgs["CVE-2"] = []model.Configuration{config("CVE-2", "OR", false, node("OR", false, match("CVE-2", "cpe:2.3:a:v:two:*:*:*:*:*:*:*:*", true)))}

	res := resolveWith(t, s, []string{"cpe:/a:v:one:1.0", "cpe:/a:v:two:1.0"}, "1.0")
	if len(res.Matches) != 2 {
		t.Fatalf("expected 2 matches (deduped), got %d: %+v", len(res.Matches), res.Matches)
	}
	seen := map[string]bool{}
	for _, m := range res.Matches {
		if seen[m.CVEID] {
			t.Fatalf("duplicate CVE in matches: %s", m.CVEID)
		}
		seen[m.CVEID] = true
	}
	if !seen["CVE-1"] || !seen["CVE-2"] {
		t.Fatalf("expected CVE-1 and CVE-2, got %v", seen)
	}
}

func TestLowConfidenceInput(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true))
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{
		CPEs: []string{"cpe:/a:v:p:1.0"}, Method: "table", Confidence: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", res)
	}
	if res.Matches[0].MatchConfidence != model.ConfidenceLow {
		t.Fatalf("confidence = %v, want LOW", res.Matches[0].MatchConfidence)
	}
}

func TestInsufficientData(t *testing.T) {
	s := newStore()
	res := resolveWith(t, s, nil, "")
	if len(res.Matches) != 0 || len(res.Uncertain) != 0 || len(res.NotMatched) != 0 {
		t.Fatalf("expected empty resolution, got %+v", res)
	}
}

func TestUnparseableCPE(t *testing.T) {
	s := newStore()
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"garbage"}, Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("expected no matches for unparseable cpe, got %+v", res)
	}
	if res.Insufficient != 1 {
		t.Fatalf("insufficient = %d, want 1", res.Insufficient)
	}
}

func TestReasonContainsRange(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, sp("1.2.0"), nil, nil, sp("1.4.0")))
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.3.0"}, "1.3.0")
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", res)
	}
	if !strings.Contains(res.Matches[0].Reason, "1.2.0") || !strings.Contains(res.Matches[0].Reason, "1.4.0") {
		t.Fatalf("reason missing range: %s", res.Matches[0].Reason)
	}
}

// --- concrete / wildcard / NA / missing criteria version (exact-version fix) ---

func TestConcreteCriteriaVersionMismatch(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:openbsd:openssh:1.2.27:*:*:*:*:*:*:*", true))
	res := resolveWith(t, s, []string{"cpe:/a:openbsd:openssh:9.6p1"}, "9.6p1")
	if len(res.Matches) != 0 {
		t.Fatalf("expected no MATCHED, got %+v", res.Matches)
	}
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED", got)
	}
}

func TestConcreteCriteriaVersionEqual(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*", true))
	s.vulns["CVE-1"] = model.Vulnerability{CVEID: "CVE-1"}
	res := resolveWith(t, s, []string{"cpe:/a:openbsd:openssh:9.6p1"}, "9.6p1")
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", res.Matches)
	}
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestWildcardCriteriaNoRange(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true))
	res := resolveWith(t, s, []string{"cpe:/a:v:p:9.6p1"}, "9.6p1")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestWildcardCriteriaWithRangeInside(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-1", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", true, sp("9.0"), nil, nil, sp("9.7")))
	res := resolveWith(t, s, []string{"cpe:/a:openbsd:openssh:9.6p1"}, "9.6p1")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestWildcardCriteriaWithRangeOutside(t *testing.T) {
	s := oneRuleStore(rangedMatch("CVE-1", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", true, sp("9.0"), nil, nil, sp("9.7")))
	res := resolveWith(t, s, []string{"cpe:/a:openbsd:openssh:9.8"}, "9.8")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED", got)
	}
}

func TestNACriteriaVersion(t *testing.T) {
	s := oneRuleStore(match("CVE-1", "cpe:2.3:a:v:p:-:*:*:*:*:*:*:*", true))
	res := resolveWith(t, s, []string{"cpe:/a:v:p:9.6p1"}, "9.6p1")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED", got)
	}
}

func TestMissingCriteriaVersion(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	m := match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true)
	m.Version = ""
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false, node("OR", false, m))}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:9.6p1"}, "9.6p1")
	if len(res.Uncertain) != 1 {
		t.Fatalf("expected 1 UNCERTAIN, got %+v", res.Uncertain)
	}
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN", got)
	}
}

func TestOpenSSHOldConcreteVersionRegression(t *testing.T) {
	s := newStore()
	s.candidateCVEs["openbsd|openssh"] = []string{"CVE-2020-0001", "CVE-2020-0002"}
	s.cfgs["CVE-2020-0001"] = []model.Configuration{config("CVE-2020-0001", "OR", false,
		node("OR", false, match("CVE-2020-0001", "cpe:2.3:a:openbsd:openssh:1.2.27:*:*:*:*:*:*:*", true)))}
	s.cfgs["CVE-2020-0002"] = []model.Configuration{config("CVE-2020-0002", "OR", false,
		node("OR", false, match("CVE-2020-0002", "cpe:2.3:a:openbsd:openssh:4.5:*:*:*:*:*:*:*", true)))}
	s.vulns["CVE-2020-0001"] = model.Vulnerability{CVEID: "CVE-2020-0001"}
	s.vulns["CVE-2020-0002"] = model.Vulnerability{CVEID: "CVE-2020-0002"}

	res := resolveWith(t, s, []string{"cpe:/a:openbsd:openssh:9.6p1"}, "9.6p1")
	if len(res.Matches) != 0 {
		t.Fatalf("CVEs with concrete old versions must NOT appear in Matches, got %+v", res.Matches)
	}
	for _, id := range []string{"CVE-2020-0001", "CVE-2020-0002"} {
		if got := findState(res, id); got != model.StateNotMatched {
			t.Fatalf("%s state = %v, want NOT_MATCHED", id, got)
		}
	}
}

// --- configuration tree evaluation ---

func TestOrSatisfiedByAnyBranch(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false,
			match("CVE-1", "cpe:2.3:a:v:other:*:*:*:*:*:*:*:*", true),
			match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.0"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
	if !strings.Contains(res.Matches[0].Reason, "v:p") || !strings.Contains(res.Matches[0].Reason, "OR") {
		t.Fatalf("reason should describe satisfied OR branch: %s", res.Matches[0].Reason)
	}
}

func TestAndBothMatch(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|app"] = []string{"CVE-1"}
	s.candidateCVEs["v|os"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "AND", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:app:*:*:*:*:*:*:*:*", true)),
		node("OR", false, match("CVE-1", "cpe:2.3:o:v:os:*:*:*:*:*:*:*:*", false)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:app:1.0", "cpe:/o:v:os:1.0"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED (got %s)", got, reasonOf(res, "CVE-1"))
	}
}

func TestAndFailure(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|app"] = []string{"CVE-1"}
	s.candidateCVEs["v|os"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "AND", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:app:*:*:*:*:*:*:*:*", true)),
		node("OR", false, match("CVE-1", "cpe:2.3:o:v:os:*:*:*:*:*:*:*:*", false)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:app:1.0"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED (missing required os condition)", got)
	}
}

func TestAndUncertainty(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|app"] = []string{"CVE-1"}
	s.candidateCVEs["v|os"] = []string{"CVE-1"}
	// os condition has a concrete version and the input os has no version -> UNCERTAIN
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "AND", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:app:*:*:*:*:*:*:*:*", true)),
		node("OR", false, match("CVE-1", "cpe:2.3:o:v:os:1.0:*:*:*:*:*:*:*", false)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:app:1.0", "cpe:/o:v:os"}, "")
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN (required os version unknown), reason=%s", got, reasonOf(res, "CVE-1"))
	}
}

func TestAndBothUncertain(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|app"] = []string{"CVE-1"}
	s.candidateCVEs["v|os"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "AND", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:app:2.0:*:*:*:*:*:*:*", true)),
		node("OR", false, match("CVE-1", "cpe:2.3:o:v:os:1.0:*:*:*:*:*:*:*", false)),
	)}
	// input versions do not resolve any condition exactly
	res := resolveWith(t, s, []string{"cpe:/a:v:app:1.0"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED (app version mismatch makes AND fail)", got)
	}
}

func reasonOf(res *Result, cveID string) string {
	for _, m := range res.Matches {
		if m.CVEID == cveID {
			return m.Reason
		}
	}
	for _, m := range res.Uncertain {
		if m.CVEID == cveID {
			return m.Reason
		}
	}
	for _, m := range res.NotMatched {
		if m.CVEID == cveID {
			return m.Reason
		}
	}
	return ""
}

func TestVulnerableFalseEnvironmentCondition(t *testing.T) {
	s := newStore()
	s.candidateCVEs["microsoft|windows_10"] = []string{"CVE-1"}
	s.candidateCVEs["microsoft|server_message_block"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "AND", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:microsoft:server_message_block:1.0:*:*:*:*:*:*:*", true)),
		node("OR", false,
			match("CVE-1", "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:x64:*", false),
			match("CVE-1", "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:x86:*", false)),
	)}

	// only the vulnerable application -> required OS platform missing -> NOT_MATCHED
	res := resolveWith(t, s, []string{"cpe:/a:microsoft:server_message_block:1.0"}, "")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED without required platform condition", got)
	}

	// app + matching x64 windows -> MATCHED
	res2 := resolveWith(t, s, []string{
		"cpe:/a:microsoft:server_message_block:1.0",
		"cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:x64:*",
	}, "")
	if got := findState(res2, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED with platform condition present", got)
	}

	// app + windows x86 (not x64) -> the windows node still OR-matches -> MATCHED
	res3 := resolveWith(t, s, []string{
		"cpe:/a:microsoft:server_message_block:1.0",
		"cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:x86:*",
	}, "")
	if got := findState(res3, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED with x86 platform condition", got)
	}
}

func TestNegatedNode(t *testing.T) {
	// NOT(no app installed) semantics: node is negated AND(negate flag).
	// negated MATCHED -> NOT_MATCHED
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", true, match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.0"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("negated MATCHED -> state = %v, want NOT_MATCHED", got)
	}

	// negated NOT_MATCHED -> MATCHED
	s2 := newStore()
	s2.candidateCVEs["v|p"] = []string{"CVE-1"}
	s2.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", true, match("CVE-1", "cpe:2.3:a:v:other:*:*:*:*:*:*:*:*", true)),
	)}
	res2 := resolveWith(t, s2, []string{"cpe:/a:v:p:1.0"}, "1.0")
	if got := findState(res2, "CVE-1"); got != model.StateMatched {
		t.Fatalf("negated NOT_MATCHED -> state = %v, want MATCHED", got)
	}

	// negated UNCERTAIN stays UNCERTAIN
	s3 := newStore()
	s3.candidateCVEs["v|p"] = []string{"CVE-1"}
	s3.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", true, match("CVE-1", "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", true)),
	)}
	res3 := resolveWith(t, s3, []string{"cpe:/a:v:p"}, "")
	if got := findState(res3, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("negated UNCERTAIN -> state = %v, want UNCERTAIN", got)
	}
}

func TestNegatedConfiguration(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	// configuration negated: NOT(app matches) -> NOT_MATCHED
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", true,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.0"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("negated configuration -> state = %v, want NOT_MATCHED", got)
	}
}

func TestSameCVEMultipleBranches(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:alpha:*:*:*:*:*:*:*:*", true)),
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true)),
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:gamma:*:*:*:*:*:*:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.0"}, "1.0")
	if len(res.Matches) != 1 {
		t.Fatalf("expected single CVE matched, got %+v", res)
	}
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestDuplicateCriteriaDifferentRanges(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	// two rules with identical criteria but different end ranges survive as
	// separate branches; the <4.0 branch matches 3.0 -> MATCHED
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, nil, nil, nil, sp("2.0"))),
		node("OR", false, rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, nil, nil, nil, sp("4.0"))),
	)}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:3.0"}, "3.0")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED via the <4.0 branch", got)
	}
}

// --- restrictive CPE components, wildcard, NA, escaping ---

func TestRestrictiveTargetSWMismatch(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:1.0:*:*:*:*:linux:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:2.3:a:v:p:1.0:*:*:*:*:windows:*:*"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("target_sw linux vs windows -> state = %v, want NOT_MATCHED", got)
	}
}

func TestRestrictiveTargetSWMatch(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:1.0:*:*:*:*:linux:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:2.3:a:v:p:1.0:*:*:*:*:linux:*:*"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("target_sw linux vs linux -> state = %v, want MATCHED", got)
	}
}

func TestWildcardComponent(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	// criteria target_sw is wildcard; input windows -> matches
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:2.3:a:v:p:1.0:*:*:*:*:windows:*:*"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("wildcard target_sw -> state = %v, want MATCHED", got)
	}
}

func TestNAComponent(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	// criteria edition NA; input edition concrete -> NOT_MATCHED
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:1.0:*:-:*:*:*:*:*", true)),
	)}
	res := resolveWith(t, s, []string{"cpe:2.3:a:v:p:1.0:*:ed:*:*:*:*:*"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("NA edition vs concrete -> state = %v, want NOT_MATCHED", got)
	}

	// input edition NA too -> MATCHED
	s2 := newStore()
	s2.candidateCVEs["v|p"] = []string{"CVE-1"}
	s2.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", "cpe:2.3:a:v:p:1.0:*:-:*:*:*:*:*", true)),
	)}
	res2 := resolveWith(t, s2, []string{"cpe:2.3:a:v:p:1.0:*:-:*:*:*:*:*"}, "1.0")
	if got := findState(res2, "CVE-1"); got != model.StateMatched {
		t.Fatalf("NA edition vs NA -> state = %v, want MATCHED", got)
	}
}

func TestEscapedLiteralNotWildcard(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	// criteria update is an escaped literal "*" (not a wildcard); input update
	// is a wildcard, so the concrete literal cannot be confirmed -> UNCERTAIN
	s.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", `cpe:2.3:a:v:p:1.0:\*:*:*:*:*:*:*`, true)),
	)}
	res := resolveWith(t, s, []string{"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}, "1.0")
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("escaped literal * must not act as wildcard -> state = %v, want UNCERTAIN", got)
	}

	// escaped literal matched against an identical escaped literal -> MATCHED
	s2 := newStore()
	s2.candidateCVEs["v|p"] = []string{"CVE-1"}
	s2.cfgs["CVE-1"] = []model.Configuration{config("CVE-1", "OR", false,
		node("OR", false, match("CVE-1", `cpe:2.3:a:v:p:1.0:\*:*:*:*:*:*:*`, true)),
	)}
	res2 := resolveWith(t, s2, []string{`cpe:2.3:a:v:p:1.0:\*:*:*:*:*:*:*`}, "1.0")
	if got := findState(res2, "CVE-1"); got != model.StateMatched {
		t.Fatalf("escaped literal matching escaped literal -> state = %v, want MATCHED", got)
	}
}

// --- legacy (pre-resync) flattened rows ---

func TestLegacyFlatRowsStillResolve(t *testing.T) {
	s := newStore()
	s.candidateCVEs["v|p"] = []string{"CVE-1"}
	s.legacy["CVE-1"] = []model.CPEMatch{
		rangedMatch("CVE-1", "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", true, sp("1.0"), nil, nil, sp("2.0")),
	}
	res := resolveWith(t, s, []string{"cpe:/a:v:p:1.5"}, "1.5")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("legacy flat row -> state = %v, want MATCHED", got)
	}
}