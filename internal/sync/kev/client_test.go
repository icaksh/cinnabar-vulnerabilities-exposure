package kev

import (
	"encoding/json"
	"testing"
)

func TestParseKEV(t *testing.T) {
	raw := `{"vulnerabilities": [
		{
			"cveID": "CVE-2021-44228",
			"vendorProject": "Apache",
			"product": "Log4j2",
			"vulnerabilityName": "Apache Log4j2 Remote Code Execution",
			"dateAdded": "2021-12-10",
			"shortDescription": "desc",
			"requiredAction": "Apply updates per vendor instructions.",
			"dueDate": "2021-12-24",
			"knownRansomwareCampaignUse": "Known",
			"notes": "",
			"cwes": ["CWE-502"]
		},
		{
			"cveID": "CVE-2022-0001",
			"vendorProject": "X",
			"product": "Y",
			"dateAdded": "2022-01-01",
			"requiredAction": "",
			"dueDate": "2022-01-15",
			"knownRansomwareCampaignUse": ""
		}
	]}`
	var f feed
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entries := Parse(f)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	e := entries[0]
	if e.CVEID != "CVE-2021-44228" {
		t.Fatalf("cve id = %v", e.CVEID)
	}
	if e.DateAdded == nil || e.DateAdded.Format("2006-01-02") != "2021-12-10" {
		t.Fatalf("date added = %v", e.DateAdded)
	}
	if e.DueDate == nil || e.DueDate.Format("2006-01-02") != "2021-12-24" {
		t.Fatalf("due date = %v", e.DueDate)
	}
	if e.RequiredAction == nil || *e.RequiredAction != "Apply updates per vendor instructions." {
		t.Fatalf("required action = %v", e.RequiredAction)
	}
	if !e.KnownRansomwareCampaignUse {
		t.Fatalf("expected ransomware flag true")
	}
	if e.Raw == nil {
		t.Fatalf("expected raw json")
	}

	e2 := entries[1]
	if e2.RequiredAction != nil {
		t.Fatalf("expected nil required action, got %v", *e2.RequiredAction)
	}
	if e2.KnownRansomwareCampaignUse {
		t.Fatalf("expected ransomware flag false")
	}
}
