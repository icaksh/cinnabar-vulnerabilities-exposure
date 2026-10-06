package db

import (
	"context"
	"os"
	"testing"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

// TestConfigurationTreeRoundTrip exercises ReplaceConfigurations /
// GetConfigurations / CandidateCVEs / GetLegacyMatches against a real
// PostgreSQL. It is skipped unless TEST_DATABASE_URL is set.
func TestConfigurationTreeRoundTrip(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB integration test")
	}
	ctx := context.Background()

	d, err := New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	const cve = "ITEST-0001"
	cleanup := func() {
		_ = d.ReplaceConfigurations(ctx, []string{cve}, nil)
		_, _ = d.pool.Exec(ctx, `DELETE FROM vulnerability_cpe_matches WHERE cve_id = $1`, cve)
		_, _ = d.pool.Exec(ctx, `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	}
	cleanup()
	defer cleanup()

	if _, err := d.pool.Exec(ctx, `INSERT INTO vulnerabilities (cve_id, description, severity) VALUES ($1, 'itest', 'HIGH')`, cve); err != nil {
		t.Fatal(err)
	}

	cfg := model.Configuration{
		CVEID:    cve,
		Operator: "AND",
		Negate:   false,
		Position: 0,
		Nodes: []model.ConfigurationNode{
			{
				Operator: "OR",
				Position: 0,
				Matches: []model.CPEMatch{{
					CVEID: cve, MatchCriteriaID: "IT-M1",
					Criteria: "cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", Part: "a", Vendor: "acme", Product: "app",
					Version: "*", Update: "*", Edition: "*", Language: "*", Vulnerable: true,
				}},
			},
			{
				Operator: "OR",
				Position: 1,
				Matches: []model.CPEMatch{
					{
						CVEID: cve, MatchCriteriaID: "IT-M2",
						Criteria: "cpe:2.3:o:acme:os:*:*:*:*:*:x64:*", Part: "o", Vendor: "acme", Product: "os",
						Version: "*", Update: "*", Edition: "*", Language: "*", TargetHW: "x64", Vulnerable: false,
					},
					{
						CVEID: cve, MatchCriteriaID: "IT-M2b",
						Criteria: "cpe:2.3:o:acme:os:*:*:*:*:*:x86:*", Part: "o", Vendor: "acme", Product: "os",
						Version: "*", Update: "*", Edition: "*", Language: "*", TargetHW: "x86", Vulnerable: false,
					},
				},
			},
		},
	}

	if err := d.ReplaceConfigurations(ctx, []string{cve}, map[string][]model.Configuration{cve: {cfg}}); err != nil {
		t.Fatal(err)
	}

	// Candidate discovery by vulnerable product AND by vulnerable=false platform.
	ids, err := d.CandidateCVEs(ctx, "a", "acme", "app")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(ids, cve) {
		t.Fatalf("CandidateCVEs(app) = %v, want to contain %s", ids, cve)
	}
	osIDs, err := d.CandidateCVEs(ctx, "o", "acme", "os")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(osIDs, cve) {
		t.Fatalf("CandidateCVEs(os) = %v, want to contain %s (vulnerable=false must still discover)", osIDs, cve)
	}

	got, err := d.GetConfigurations(ctx, []string{cve})
	if err != nil {
		t.Fatal(err)
	}
	cfgs := got[cve]
	if len(cfgs) != 1 {
		t.Fatalf("configs = %d, want 1", len(cfgs))
	}
	c := cfgs[0]
	if c.Operator != "AND" || c.Negate {
		t.Fatalf("configuration wrong: %+v", c)
	}
	if len(c.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(c.Nodes))
	}
	if c.Nodes[0].Matches[0].MatchCriteriaID != "IT-M1" || c.Nodes[0].Matches[0].Vendor != "acme" {
		t.Fatalf("node0 wrong: %+v", c.Nodes[0])
	}
	envNode := c.Nodes[1]
	if len(envNode.Matches) != 2 {
		t.Fatalf("env node matches = %d, want 2 (same criteria/different hw must both survive)", len(envNode.Matches))
	}
	if envNode.Matches[0].Vulnerable {
		t.Fatalf("vulnerable flag lost: %+v", envNode.Matches[0])
	}
	if envNode.Matches[0].TargetHW != "x64" || envNode.Matches[1].TargetHW != "x86" {
		t.Fatalf("target_hw components wrong: %+v", envNode.Matches)
	}

	// Legacy (node_id NULL) rows load via GetLegacyMatches.
	_, err = d.pool.Exec(ctx, `INSERT INTO vulnerability_cpe_matches
		(cve_id, match_criteria_id, criteria, part, vendor, product, version, vulnerable)
		VALUES ($1, 'IT-LEGACY', 'cpe:2.3:a:acme:old:*:*:*:*:*:*:*:*', 'a', 'acme', 'old', '*', true)`, cve)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := d.GetLegacyMatches(ctx, []string{cve})
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy[cve]) != 1 || legacy[cve][0].MatchCriteriaID != "IT-LEGACY" {
		t.Fatalf("legacy matches = %+v, want 1 legacy row", legacy[cve])
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}