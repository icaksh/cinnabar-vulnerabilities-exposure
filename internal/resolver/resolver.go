package resolver

import (
	"context"
	"sort"
	"strings"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/cpe"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/version"
)

type Store interface {
	CandidateCVEs(ctx context.Context, part, vendor, product string) ([]string, error)
	GetConfigurations(ctx context.Context, cveIDs []string) (map[string][]model.Configuration, error)
	GetLegacyMatches(ctx context.Context, cveIDs []string) (map[string][]model.CPEMatch, error)
	GetVulnerabilitiesByIDs(ctx context.Context, ids []string) (map[string]model.Vulnerability, error)
}

type Resolver struct {
	store Store
}

type Result struct {
	Matches      []model.Match
	Uncertain    []model.Match
	NotMatched   []model.Match
	Insufficient int
}

func New(store Store) *Resolver {
	return &Resolver{store: store}
}

type input struct {
	raw string
	c   *cpe.CPE
	ver *string
}

func (r *Resolver) Resolve(ctx context.Context, req model.ResolveRequest) (*Result, error) {
	res := &Result{}

	var inputs []input
	insufficient := 0
	usable := false
	for _, raw := range req.CPEs {
		c, err := cpe.Parse(raw)
		if err != nil {
			insufficient++
			continue
		}
		if c.VendorLower() == cpe.Any || c.ProductLower() == cpe.Any {
			insufficient++
			continue
		}
		usable = true
		inputs = append(inputs, input{raw: raw, c: c, ver: resolveVersion(c, req.Version)})
	}
	if !usable {
		res.Insufficient = insufficient
		return res, nil
	}

	// 1. Candidate CVE discovery via indexed (part, vendor, product) lookup.
	candSet := map[string]bool{}
	for _, in := range inputs {
		part := ""
		if !in.c.IsAnyPart() {
			part = in.c.PartLower()
		}
		ids, err := r.store.CandidateCVEs(ctx, part, in.c.VendorLower(), in.c.ProductLower())
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			candSet[id] = true
		}
	}
	ids := make([]string, 0, len(candSet))
	for id := range candSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// 2. Batch-load the full applicability trees for all candidates.
	cfgsByCVE, err := r.store.GetConfigurations(ctx, ids)
	if err != nil {
		return nil, err
	}
	legacyByCVE, err := r.store.GetLegacyMatches(ctx, ids)
	if err != nil {
		return nil, err
	}
	vulns, err := r.store.GetVulnerabilitiesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}

	versionShown := detectedVersion(req, inputs)

	// 3. Evaluate each candidate CVE's full expression in memory.
	for _, id := range ids {
		var ev evalResult
		switch {
		case len(cfgsByCVE[id]) > 0:
			ev = evalConfigs(cfgsByCVE[id], inputs)
		case len(legacyByCVE[id]) > 0:
			ev = evalLegacy(legacyByCVE[id], inputs)
		default:
			ev = evalResult{state: model.StateNotMatched, certain: true,
				expr: "no applicability data stored for candidate CVE"}
		}

		m := model.Match{
			CVEID:           id,
			State:           ev.state,
			MatchedInputCPE: ev.inputCPE,
			MatchedCriteria: ev.criteria,
			Version:         versionShown,
			MatchConfidence: computeConfidence(req, ev.certain),
			Reason:          reasonString(ev),
		}
		if v, ok := vulns[id]; ok {
			m.Severity = v.Severity
			m.CVSS = v.CVSSScore
			m.IsKEV = v.IsKEV
		}
		switch ev.state {
		case model.StateMatched:
			res.Matches = append(res.Matches, m)
		case model.StateUncertain:
			res.Uncertain = append(res.Uncertain, m)
		default:
			res.NotMatched = append(res.NotMatched, m)
		}
	}

	res.Insufficient = insufficient
	return res, nil
}

func detectedVersion(req model.ResolveRequest, inputs []input) string {
	if strings.TrimSpace(req.Version) != "" {
		return strings.TrimSpace(req.Version)
	}
	if len(inputs) > 0 && inputs[0].ver != nil {
		return *inputs[0].ver
	}
	return ""
}

func resolveVersion(c *cpe.CPE, reqVersion string) *string {
	if c.HasVersion() {
		v := c.VersionValue()
		return &v
	}
	if strings.TrimSpace(reqVersion) != "" {
		v := strings.TrimSpace(reqVersion)
		return &v
	}
	return nil
}

// evalResult carries a 4-state result plus an auditable expression trace and
// the first matching leaf (criteria + input CPE) for display.
type evalResult struct {
	state    model.MatchState
	certain  bool
	expr     string
	criteria string
	inputCPE string
}

func reasonString(ev evalResult) string {
	switch ev.state {
	case model.StateMatched:
		return "matched: " + ev.expr
	case model.StateUncertain:
		return "uncertain: " + ev.expr
	default:
		return "not matched: " + ev.expr
	}
}

func evalConfigs(cfgs []model.Configuration, inputs []input) evalResult {
	rs := make([]evalResult, 0, len(cfgs))
	for _, c := range cfgs {
		rs = append(rs, evalConfiguration(c, inputs))
	}
	return combineResults("OR", rs, false)
}

func evalConfiguration(c model.Configuration, inputs []input) evalResult {
	rs := make([]evalResult, 0, len(c.Nodes))
	for _, n := range c.Nodes {
		rs = append(rs, evalNode(n, inputs))
	}
	return combineResults(c.Operator, rs, c.Negate)
}

func evalNode(n model.ConfigurationNode, inputs []input) evalResult {
	rs := make([]evalResult, 0, len(n.Matches)+len(n.Children))
	for _, m := range n.Matches {
		rs = append(rs, evalLeaf(m, inputs))
	}
	for _, ch := range n.Children {
		rs = append(rs, evalNode(ch, inputs))
	}
	return combineResults(n.Operator, rs, n.Negate)
}

func evalLegacy(ms []model.CPEMatch, inputs []input) evalResult {
	rs := make([]evalResult, 0, len(ms))
	for _, m := range ms {
		rs = append(rs, evalLeaf(m, inputs))
	}
	return combineResults("OR", rs, false)
}

func evalLeaf(m model.CPEMatch, inputs []input) evalResult {
	label := leafLabel(m)
	matched := false
	matchedCertain := false
	uncertain := false
	var matchedInput string
	for _, in := range inputs {
		st, cert := evalLeafInput(m, in)
		switch st {
		case model.StateMatched:
			matched = true
			if cert {
				matchedCertain = true
			}
			if matchedInput == "" {
				matchedInput = in.raw
			}
		case model.StateUncertain:
			uncertain = true
		}
	}
	var st model.MatchState
	var certain bool
	switch {
	case matched:
		st = model.StateMatched
		certain = matchedCertain
	case uncertain:
		st = model.StateUncertain
		certain = false
	default:
		st = model.StateNotMatched
		certain = true
	}
	return evalResult{state: st, certain: certain, expr: label, criteria: m.Criteria, inputCPE: matchedInput}
}

func evalLeafInput(m model.CPEMatch, in input) (model.MatchState, bool) {
	vst, vcert := evalVersion(m, in.ver)
	cst, ccert := evalComponents(m, in.c)
	if vst == model.StateNotMatched || cst == model.StateNotMatched {
		return model.StateNotMatched, true
	}
	if vst == model.StateUncertain || cst == model.StateUncertain {
		return model.StateUncertain, false
	}
	return model.StateMatched, vcert && ccert
}

// combineResults applies a 4-state AND/OR (with optional negation) over child
// results. Unknown states are never collapsed into MATCHED.
func combineResults(op string, rs []evalResult, negate bool) evalResult {
	if len(rs) == 0 {
		return evalResult{state: model.StateUncertain, certain: false, expr: "empty expression"}
	}
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, r.expr)
	}
	joiner := " AND "
	if op == "OR" {
		joiner = " OR "
	}
	expr := ""
	if len(parts) == 1 {
		expr = parts[0]
	} else {
		expr = "(" + strings.Join(parts, joiner) + ")"
	}

	state := combineState(op, rs)
	certain := combineCertain(op, state, rs)
	if negate {
		state = negateState(state)
		expr = "NOT(" + expr + ")"
	}

	criteria, inputCPE := "", ""
	for _, r := range rs {
		if r.criteria != "" {
			criteria = r.criteria
		}
		if r.inputCPE != "" {
			inputCPE = r.inputCPE
		}
		if criteria != "" && inputCPE != "" {
			break
		}
	}
	return evalResult{state: state, certain: certain, expr: expr, criteria: criteria, inputCPE: inputCPE}
}

func combineState(op string, rs []evalResult) model.MatchState {
	if op == "AND" {
		state := model.StateMatched
		for _, r := range rs {
			switch r.state {
			case model.StateNotMatched:
				return model.StateNotMatched
			case model.StateUncertain:
				state = model.StateUncertain
			}
		}
		return state
	}
	// OR
	state := model.StateNotMatched
	for _, r := range rs {
		switch r.state {
		case model.StateMatched:
			return model.StateMatched
		case model.StateUncertain:
			state = model.StateUncertain
		}
	}
	return state
}

func combineCertain(op string, state model.MatchState, rs []evalResult) bool {
	if op == "OR" && state == model.StateMatched {
		for _, r := range rs {
			if r.state == model.StateMatched && r.certain {
				return true
			}
		}
		return false
	}
	for _, r := range rs {
		if !r.certain {
			return false
		}
	}
	return true
}

func negateState(s model.MatchState) model.MatchState {
	switch s {
	case model.StateMatched:
		return model.StateNotMatched
	case model.StateNotMatched:
		return model.StateMatched
	default:
		return s
	}
}

// evalVersion preserves the previous concrete/wildcard/NA/range semantics.
func evalVersion(m model.CPEMatch, ver *string) (model.MatchState, bool) {
	cv := strings.TrimSpace(m.Version)

	if ver == nil {
		switch {
		case isConcreteVersion(cv):
			return model.StateUncertain, false
		case cv == cpe.Any:
			if hasBoundaries(m) {
				return model.StateUncertain, false
			}
			return model.StateMatched, false
		case cv == cpe.NA:
			return model.StateNotMatched, true
		default:
			return model.StateUncertain, false
		}
	}

	v := *ver
	switch {
	case isConcreteVersion(cv):
		if !versionsEqual(v, cv) {
			return model.StateNotMatched, true
		}
	case cv == cpe.Any:
	case cv == cpe.NA:
		return model.StateNotMatched, true
	default:
		return model.StateUncertain, false
	}

	if !hasBoundaries(m) {
		return model.StateMatched, true
	}

	certain := true
	if m.VersionStartIncl != nil {
		switch version.Compare(v, *m.VersionStartIncl) {
		case version.Less:
			return model.StateNotMatched, true
		case version.Uncertain:
			certain = false
		}
	}
	if m.VersionStartExcl != nil {
		switch version.Compare(v, *m.VersionStartExcl) {
		case version.Less, version.Equal:
			return model.StateNotMatched, true
		case version.Uncertain:
			certain = false
		}
	}
	if m.VersionEndIncl != nil {
		switch version.Compare(v, *m.VersionEndIncl) {
		case version.Greater:
			return model.StateNotMatched, true
		case version.Uncertain:
			certain = false
		}
	}
	if m.VersionEndExcl != nil {
		switch version.Compare(v, *m.VersionEndExcl) {
		case version.Greater, version.Equal:
			return model.StateNotMatched, true
		case version.Uncertain:
			certain = false
		}
	}
	if !certain {
		return model.StateUncertain, false
	}
	return model.StateMatched, true
}

// evalComponents evaluates the restrictive CPE components (part/vendor/product
// plus update/edition/language/sw_edition/target_sw/target_hw/other) using
// conservative wildcard/NA/concrete semantics.
func evalComponents(m model.CPEMatch, c *cpe.CPE) (model.MatchState, bool) {
	pairs := [][]string{
		{m.Part, c.Part}, {m.Vendor, c.Vendor}, {m.Product, c.Product},
		{m.Update, c.Update}, {m.Edition, c.Edition}, {m.Language, c.Language},
		{m.SWEdition, c.SWEdition}, {m.TargetSW, c.TargetSW}, {m.TargetHW, c.TargetHW}, {m.Other, c.Other},
	}
	state := model.StateMatched
	certain := true
	for _, p := range pairs {
		st, cert := componentMatch(p[0], p[1])
		switch st {
		case model.StateNotMatched:
			return model.StateNotMatched, true
		case model.StateUncertain:
			state = model.StateUncertain
		}
		if !cert {
			certain = false
		}
	}
	return state, certain
}

func componentMatch(critVal, inputVal string) (model.MatchState, bool) {
	cv := strings.TrimSpace(critVal)
	iv := strings.TrimSpace(inputVal)
	switch {
	case cv == "" || cv == cpe.Any:
		return model.StateMatched, true
	case cv == cpe.NA:
		switch iv {
		case cpe.NA:
			return model.StateMatched, true
		case "", cpe.Any:
			return model.StateUncertain, false
		default:
			return model.StateNotMatched, true
		}
	default:
		switch iv {
		case cpe.NA:
			return model.StateNotMatched, true
		case "", cpe.Any:
			return model.StateUncertain, false
		default:
			if componentsEqual(cv, iv) {
				return model.StateMatched, true
			}
			return model.StateNotMatched, true
		}
	}
}

func componentsEqual(a, b string) bool {
	return strings.ToLower(strings.TrimSpace(a)) == strings.ToLower(strings.TrimSpace(b))
}

func leafLabel(m model.CPEMatch) string {
	s := m.Vendor + ":" + m.Product
	if m.Version != "" && m.Version != cpe.Any {
		s += ":" + m.Version
	}
	if r := rangeString(m); r != "all versions" {
		s += " " + r
	}
	if m.Vulnerable {
		s += " [vuln]"
	} else {
		s += " [env]"
	}
	return s
}

func isConcreteVersion(cv string) bool {
	return cv != "" && cv != cpe.Any && cv != cpe.NA
}

func versionsEqual(a, b string) bool {
	return strings.ToLower(strings.TrimSpace(a)) == strings.ToLower(strings.TrimSpace(b))
}

func hasBoundaries(m model.CPEMatch) bool {
	return m.VersionStartIncl != nil || m.VersionStartExcl != nil || m.VersionEndIncl != nil || m.VersionEndExcl != nil
}

func rangeString(m model.CPEMatch) string {
	var lo, hi string
	switch {
	case m.VersionStartIncl != nil:
		lo = ">=" + *m.VersionStartIncl
	case m.VersionStartExcl != nil:
		lo = ">" + *m.VersionStartExcl
	}
	switch {
	case m.VersionEndIncl != nil:
		hi = "<=" + *m.VersionEndIncl
	case m.VersionEndExcl != nil:
		hi = "<" + *m.VersionEndExcl
	}
	switch {
	case lo != "" && hi != "":
		return lo + " and " + hi
	case lo != "":
		return lo
	case hi != "":
		return hi
	default:
		return "all versions"
	}
}

func computeConfidence(req model.ResolveRequest, versionCertain bool) model.MatchConfidence {
	fp := fingerprintStrength(req.Method, req.Confidence)
	var vc model.MatchConfidence
	if versionCertain {
		vc = model.ConfidenceHigh
	} else {
		vc = model.ConfidenceLow
	}
	return minConfidence(fp, vc)
}

func fingerprintStrength(method string, confidence int) model.MatchConfidence {
	if method == "probed" {
		switch {
		case confidence >= 8:
			return model.ConfidenceHigh
		case confidence >= 5:
			return model.ConfidenceMedium
		default:
			return model.ConfidenceLow
		}
	}
	switch {
	case confidence >= 8:
		return model.ConfidenceMedium
	default:
		return model.ConfidenceLow
	}
}

func minConfidence(a, b model.MatchConfidence) model.MatchConfidence {
	rank := map[model.MatchConfidence]int{
		model.ConfidenceLow:    0,
		model.ConfidenceMedium: 1,
		model.ConfidenceHigh:   2,
	}
	if rank[a] <= rank[b] {
		return a
	}
	return b
}