package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/cpe"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type fakeStore struct {
	candidates map[string][]model.CPEMatch
	vulns      map[string]model.Vulnerability
}

func (f *fakeStore) CandidateLookup(_ context.Context, part, vendor, product string) ([]model.CPEMatch, error) {
	var out []model.CPEMatch
	for _, c := range f.candidates[vendor+"|"+product] {
		if part == "" || c.Part == part {
			out = append(out, c)
		}
	}
	return out, nil
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

func sp(s string) *string { return &s }

func rule(cveID, vendor, product, part, version string, startIncl, startExcl, endIncl, endExcl *string) model.CPEMatch {
	return model.CPEMatch{
		CVEID:            cveID,
		Criteria:         "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*",
		Part:             part,
		Vendor:           vendor,
		Product:          product,
		Version:          version,
		VersionStartIncl: startIncl,
		VersionStartExcl: startExcl,
		VersionEndIncl:   endIncl,
		VersionEndExcl:   endExcl,
		Vulnerable:       true,
	}
}

func ruleFromCriteria(cveID, criteria string) model.CPEMatch {
	c, err := cpe.Parse(criteria)
	if err != nil {
		panic(err)
	}
	return model.CPEMatch{
		CVEID:      cveID,
		Criteria:   criteria,
		Part:       c.PartLower(),
		Vendor:     c.VendorLower(),
		Product:    c.ProductLower(),
		Version:    c.Version,
		Vulnerable: true,
	}
}

func newStore() *fakeStore {
	return &fakeStore{
		candidates: map[string][]model.CPEMatch{},
		vulns:      map[string]model.Vulnerability{},
	}
}

func TestBoundaryRange(t *testing.T) {
	s := newStore()
	s.candidates["test|pkg"] = []model.CPEMatch{
		rule("CVE-2020-0001", "test", "pkg", "a", "*", sp("1.2.0"), nil, nil, sp("1.4.0")),
	}
	s.vulns["CVE-2020-0001"] = model.Vulnerability{CVEID: "CVE-2020-0001", Severity: model.SeverityHigh}

	r := New(s)
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
		res, err := r.Resolve(context.Background(), model.ResolveRequest{
			CPEs: []string{"cpe:/a:test:pkg:" + c.version}, Version: c.version, Method: "probed", Confidence: 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := findState(res, "CVE-2020-0001")
		if got != c.want {
			t.Errorf("version %s: state = %v, want %v", c.version, got, c.want)
		}
	}
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

func TestInclusiveExclusiveBoundaries(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", sp("1.0"), nil, sp("2.0"), nil),
	}
	s.vulns["CVE-1"] = model.Vulnerability{CVEID: "CVE-1"}

	r := New(s)
	check := func(v string, want model.MatchState) {
		res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"cpe:/a:v:p:" + v}, Method: "probed", Confidence: 10})
		if err != nil {
			t.Fatal(err)
		}
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
	s := newStore()
	s.candidates["vendor|product"] = []model.CPEMatch{
		rule("CVE-1", "vendor", "product", "a", "*", nil, nil, nil, nil),
	}
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"cpe:/a:other:thing:1.0"}, Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 || len(res.Uncertain) != 0 {
		t.Fatalf("expected no matches, got %+v", res)
	}
}

func TestMissingVersionUnbounded(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", nil, nil, nil, nil),
	}
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"cpe:/a:v:p"}, Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestMissingVersionBounded(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", sp("1.0"), nil, nil, nil),
	}
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"cpe:/a:v:p"}, Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN", got)
	}
}

func TestUncomparableVersion(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", nil, nil, sp("1.0"), nil),
	}
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"cpe:/a:v:p:1.0u1"}, Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN", got)
	}
}

func TestOpenSSH(t *testing.T) {
	s := newStore()
	s.candidates["openbsd|openssh"] = []model.CPEMatch{
		rule("CVE-2024-6387", "openbsd", "openssh", "a", "*", sp("9.0"), nil, nil, sp("9.7")),
	}
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

func fp(f float64) *float64 { return &f }

func TestMultipleCPEAndDedup(t *testing.T) {
	s := newStore()
	s.candidates["v|one"] = []model.CPEMatch{
		rule("CVE-1", "v", "one", "a", "*", nil, nil, nil, nil),
	}
	s.candidates["v|two"] = []model.CPEMatch{
		rule("CVE-2", "v", "two", "a", "*", nil, nil, nil, nil),
		rule("CVE-1", "v", "two", "a", "*", nil, nil, nil, nil),
	}
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{
		CPEs: []string{"cpe:/a:v:one:1.0", "cpe:/a:v:two:1.0"}, Method: "probed", Confidence: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
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
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", nil, nil, nil, nil),
	}
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
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
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
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", sp("1.2.0"), nil, nil, sp("1.4.0")),
	}
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{CPEs: []string{"cpe:/a:v:p:1.3.0"}, Method: "probed", Confidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", res)
	}
	if !strings.Contains(res.Matches[0].Reason, "1.2.0") || !strings.Contains(res.Matches[0].Reason, "1.4.0") {
		t.Fatalf("reason missing range: %s", res.Matches[0].Reason)
	}
}

func resolveWith(t *testing.T, s *fakeStore, cpeStr, version string) *Result {
	t.Helper()
	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{
		CPEs: []string{cpeStr}, Product: "", Version: version, Method: "probed", Confidence: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestConcreteCriteriaVersionMismatch(t *testing.T) {
	s := newStore()
	s.candidates["openbsd|openssh"] = []model.CPEMatch{
		rule("CVE-1", "openbsd", "openssh", "a", "1.2.27", nil, nil, nil, nil),
	}
	res := resolveWith(t, s, "cpe:/a:openbsd:openssh:9.6p1", "9.6p1")
	if len(res.Matches) != 0 {
		t.Fatalf("expected no MATCHED, got %+v", res.Matches)
	}
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED", got)
	}
}

func TestConcreteCriteriaVersionEqual(t *testing.T) {
	s := newStore()
	s.candidates["openbsd|openssh"] = []model.CPEMatch{
		rule("CVE-1", "openbsd", "openssh", "a", "9.6p1", nil, nil, nil, nil),
	}
	s.vulns["CVE-1"] = model.Vulnerability{CVEID: "CVE-1"}
	res := resolveWith(t, s, "cpe:/a:openbsd:openssh:9.6p1", "9.6p1")
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", res.Matches)
	}
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestWildcardCriteriaNoRange(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "*", nil, nil, nil, nil),
	}
	res := resolveWith(t, s, "cpe:/a:v:p:9.6p1", "9.6p1")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestWildcardCriteriaWithRangeInside(t *testing.T) {
	s := newStore()
	s.candidates["openbsd|openssh"] = []model.CPEMatch{
		rule("CVE-1", "openbsd", "openssh", "a", "*", sp("9.0"), nil, nil, sp("9.7")),
	}
	res := resolveWith(t, s, "cpe:/a:openbsd:openssh:9.6p1", "9.6p1")
	if got := findState(res, "CVE-1"); got != model.StateMatched {
		t.Fatalf("state = %v, want MATCHED", got)
	}
}

func TestWildcardCriteriaWithRangeOutside(t *testing.T) {
	s := newStore()
	s.candidates["openbsd|openssh"] = []model.CPEMatch{
		rule("CVE-1", "openbsd", "openssh", "a", "*", sp("9.0"), nil, nil, sp("9.7")),
	}
	res := resolveWith(t, s, "cpe:/a:openbsd:openssh:9.8", "9.8")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED", got)
	}
}

func TestNACriteriaVersion(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "-", nil, nil, nil, nil),
	}
	res := resolveWith(t, s, "cpe:/a:v:p:9.6p1", "9.6p1")
	if got := findState(res, "CVE-1"); got != model.StateNotMatched {
		t.Fatalf("state = %v, want NOT_MATCHED", got)
	}
}

func TestMissingCriteriaVersion(t *testing.T) {
	s := newStore()
	s.candidates["v|p"] = []model.CPEMatch{
		rule("CVE-1", "v", "p", "a", "", nil, nil, nil, nil),
	}
	res := resolveWith(t, s, "cpe:/a:v:p:9.6p1", "9.6p1")
	if len(res.Uncertain) != 1 {
		t.Fatalf("expected 1 UNCERTAIN, got %+v", res.Uncertain)
	}
	if got := findState(res, "CVE-1"); got != model.StateUncertain {
		t.Fatalf("state = %v, want UNCERTAIN", got)
	}
}

func TestOpenSSHOldConcreteVersionRegression(t *testing.T) {
	s := newStore()
	s.candidates["openbsd|openssh"] = []model.CPEMatch{
		ruleFromCriteria("CVE-2020-0001", "cpe:2.3:a:openbsd:openssh:1.2.27:*:*:*:*:*:*:*"),
		ruleFromCriteria("CVE-2020-0002", "cpe:2.3:a:openbsd:openssh:4.5:*:*:*:*:*:*:*"),
	}
	s.vulns["CVE-2020-0001"] = model.Vulnerability{CVEID: "CVE-2020-0001"}
	s.vulns["CVE-2020-0002"] = model.Vulnerability{CVEID: "CVE-2020-0002"}

	r := New(s)
	res, err := r.Resolve(context.Background(), model.ResolveRequest{
		CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}, Product: "OpenSSH", Version: "9.6p1", Method: "probed", Confidence: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("CVEs with concrete old versions must NOT appear in Matches, got %+v", res.Matches)
	}
	for _, id := range []string{"CVE-2020-0001", "CVE-2020-0002"} {
		if got := findState(res, id); got != model.StateNotMatched {
			t.Fatalf("%s state = %v, want NOT_MATCHED", id, got)
		}
	}
}
