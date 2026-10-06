package resolver

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/cpe"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/version"
)

type Store interface {
	CandidateLookup(ctx context.Context, part, vendor, product string) ([]model.CPEMatch, error)
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

func (r *Resolver) Resolve(ctx context.Context, req model.ResolveRequest) (*Result, error) {
	res := &Result{}

	type eval struct {
		cve   string
		match model.Match
	}

	var evals []eval
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

		part := ""
		if !c.IsAnyPart() {
			part = c.PartLower()
		}
		ver := resolveVersion(c, req.Version)

		candidates, err := r.store.CandidateLookup(ctx, part, c.VendorLower(), c.ProductLower())
		if err != nil {
			return nil, err
		}
		for _, cand := range candidates {
			state, reason, certain := evaluate(cand, ver)
			m := model.Match{
				CVEID:           cand.CVEID,
				State:           state,
				MatchedInputCPE: raw,
				MatchedCriteria: cand.Criteria,
				Version:         strValue(ver),
				MatchConfidence: computeConfidence(req, certain),
				Reason:          reason,
			}
			evals = append(evals, eval{cve: cand.CVEID, match: m})
		}
	}

	if !usable {
		res.Insufficient = insufficient
		return res, nil
	}

	byCVE := map[string][]model.Match{}
	for _, e := range evals {
		byCVE[e.cve] = append(byCVE[e.cve], e.match)
	}

	ids := make([]string, 0, len(byCVE))
	for id := range byCVE {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	vulns, err := r.store.GetVulnerabilitiesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}

	for _, id := range ids {
		list := byCVE[id]
		state := model.StateNotMatched
		for _, m := range list {
			if m.State == model.StateMatched {
				state = model.StateMatched
				break
			}
			if m.State == model.StateUncertain {
				state = model.StateUncertain
			}
		}
		var best model.Match
		switch state {
		case model.StateMatched:
			best = pickFirstState(list, model.StateMatched)
		case model.StateUncertain:
			best = pickFirstState(list, model.StateUncertain)
		default:
			best = list[0]
		}
		if v, ok := vulns[id]; ok {
			best.Severity = v.Severity
			best.CVSS = v.CVSSScore
			best.IsKEV = v.IsKEV
		}
		best.State = state
		switch state {
		case model.StateMatched:
			res.Matches = append(res.Matches, best)
		case model.StateUncertain:
			res.Uncertain = append(res.Uncertain, best)
		default:
			res.NotMatched = append(res.NotMatched, best)
		}
	}

	res.Insufficient = insufficient
	return res, nil
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

func evaluate(m model.CPEMatch, ver *string) (model.MatchState, string, bool) {
	rangeStr := rangeString(m)
	cv := strings.TrimSpace(m.Version)

	if ver == nil {
		switch {
		case isConcreteVersion(cv):
			return model.StateUncertain,
				fmt.Sprintf("no version detected; cannot confirm affected version %s (%s)", cv, rangeStr), false
		case cv == cpe.Any:
			if hasBoundaries(m) {
				return model.StateUncertain,
					fmt.Sprintf("version unknown; cannot confirm affected range (%s)", rangeStr), false
			}
			return model.StateMatched,
				fmt.Sprintf("no version detected; criterion applies to all versions (%s)", rangeStr), false
		case cv == cpe.NA:
			return model.StateNotMatched,
				fmt.Sprintf("criteria version is not applicable (NA); cannot match (%s)", rangeStr), true
		default:
			return model.StateUncertain,
				fmt.Sprintf("criteria version is missing; cannot evaluate criterion (%s)", rangeStr), false
		}
	}

	v := *ver

	switch {
	case isConcreteVersion(cv):
		if !versionsEqual(v, cv) {
			return model.StateNotMatched,
				fmt.Sprintf("vendor/product matched but version %s does not equal affected version %s", v, cv), true
		}
	case cv == cpe.Any:
	case cv == cpe.NA:
		return model.StateNotMatched,
			fmt.Sprintf("vendor/product matched but criteria version %s is not applicable (NA); cannot match version %s", cv, v), true
	default:
		return model.StateUncertain,
			fmt.Sprintf("criteria version is missing; cannot evaluate version %s against criterion (%s)", v, rangeStr), false
	}

	if !hasBoundaries(m) {
		if isConcreteVersion(cv) {
			return model.StateMatched,
				fmt.Sprintf("vendor/product matched and version %s equals affected version %s", v, cv), true
		}
		return model.StateMatched,
			fmt.Sprintf("vendor/product matched and criterion applies to all versions (%s)", rangeStr), true
	}

	certain := true

	if m.VersionStartIncl != nil {
		switch version.Compare(v, *m.VersionStartIncl) {
		case version.Less:
			return model.StateNotMatched, notMatchedReason(v, rangeStr), true
		case version.Uncertain:
			certain = false
		}
	}
	if m.VersionStartExcl != nil {
		switch version.Compare(v, *m.VersionStartExcl) {
		case version.Less, version.Equal:
			return model.StateNotMatched, notMatchedReason(v, rangeStr), true
		case version.Uncertain:
			certain = false
		}
	}
	if m.VersionEndIncl != nil {
		switch version.Compare(v, *m.VersionEndIncl) {
		case version.Greater:
			return model.StateNotMatched, notMatchedReason(v, rangeStr), true
		case version.Uncertain:
			certain = false
		}
	}
	if m.VersionEndExcl != nil {
		switch version.Compare(v, *m.VersionEndExcl) {
		case version.Greater, version.Equal:
			return model.StateNotMatched, notMatchedReason(v, rangeStr), true
		case version.Uncertain:
			certain = false
		}
	}

	if !certain {
		return model.StateUncertain,
			fmt.Sprintf("version %s cannot be reliably compared against affected range (%s)", v, rangeStr), false
	}
	return model.StateMatched,
		fmt.Sprintf("vendor/product matched and version %s is inside affected range (%s)", v, rangeStr), true
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
		lo = ">= " + *m.VersionStartIncl
	case m.VersionStartExcl != nil:
		lo = "> " + *m.VersionStartExcl
	}
	switch {
	case m.VersionEndIncl != nil:
		hi = "<= " + *m.VersionEndIncl
	case m.VersionEndExcl != nil:
		hi = "< " + *m.VersionEndExcl
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

func notMatchedReason(v, rangeStr string) string {
	return fmt.Sprintf("vendor/product matched but version %s is outside affected range (%s)", v, rangeStr)
}

func strValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func pickFirstState(list []model.Match, state model.MatchState) model.Match {
	for _, m := range list {
		if m.State == state {
			return m
		}
	}
	return list[0]
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
