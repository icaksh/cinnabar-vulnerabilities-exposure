package cpe

import "testing"

func TestParse22(t *testing.T) {
	c, err := Parse("cpe:/a:openbsd:openssh:9.6p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Part != "a" || c.Vendor != "openbsd" || c.Product != "openssh" || c.Version != "9.6p1" {
		t.Fatalf("unexpected parse result: %+v", c)
	}
	if !c.HasVersion() || c.VersionValue() != "9.6p1" {
		t.Fatalf("version handling wrong: %+v", c)
	}
}

func TestParse22NoVersion(t *testing.T) {
	c, err := Parse("cpe:/o:linux:linux_kernel")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Part != "o" || c.Vendor != "linux" || c.Product != "linux_kernel" {
		t.Fatalf("unexpected parse result: %+v", c)
	}
	if c.HasVersion() {
		t.Fatalf("expected no version: %+v", c)
	}
}

func TestParse23(t *testing.T) {
	c, err := Parse("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Part != "a" || c.Vendor != "openbsd" || c.Product != "openssh" || c.Version != "9.6p1" {
		t.Fatalf("unexpected parse result: %+v", c)
	}
}

func TestParse23Truncated(t *testing.T) {
	c, err := Parse("cpe:2.3:a:openbsd:openssh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Vendor != "openbsd" || c.Product != "openssh" {
		t.Fatalf("unexpected parse result: %+v", c)
	}
	if c.Version != "*" {
		t.Fatalf("expected wildcard version, got %q", c.Version)
	}
}

func TestParseEscaped(t *testing.T) {
	c, err := Parse(`cpe:2.3:a:vendor\:name:product:1.0:*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Vendor != "vendor:name" {
		t.Fatalf("expected escaped vendor, got %q", c.Vendor)
	}
}

func TestEscapedWildcardNotWildcard(t *testing.T) {
	c, err := Parse(`cpe:2.3:a:v:p:1.0:\*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Escaped literal asterisk must not be collapsed into the ANY wildcard.
	if c.Update == Any {
		t.Fatalf("escaped literal * treated as wildcard: %+v", c)
	}
	if c.Update != `\*` {
		t.Fatalf("expected preserved escape, got %q", c.Update)
	}
}

func TestEscapedDashNotNA(t *testing.T) {
	c, err := Parse(`cpe:2.3:a:v:p:1.0:\-:*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Update == NA {
		t.Fatalf("escaped literal - treated as NA: %+v", c)
	}
	if c.Update != `\-` {
		t.Fatalf("expected preserved escape, got %q", c.Update)
	}
}

func TestWildcardAndNAComponentValues(t *testing.T) {
	c, err := Parse("cpe:2.3:a:v:p:1.0:*:-:en:sd:tlinux:arm:other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Update != "*" || c.Edition != "-" || c.Language != "en" ||
		c.SWEdition != "sd" || c.TargetSW != "tlinux" || c.TargetHW != "arm" || c.Other != "other" {
		t.Fatalf("component parsing wrong: %+v", c)
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse("not-a-cpe"); err == nil {
		t.Fatal("expected error for invalid cpe")
	}
	if _, err := Parse(""); err == nil {
		t.Fatal("expected error for empty cpe")
	}
}

func TestNormalization(t *testing.T) {
	c, _ := Parse("cpe:/A:OpenBSD:OpenSSH:9.6p1")
	if c.PartLower() != "a" || c.VendorLower() != "openbsd" || c.ProductLower() != "openssh" {
		t.Fatalf("lowercase normalization failed: %+v", c)
	}
}

func TestAnyPart(t *testing.T) {
	c, _ := Parse("cpe:2.3:*:vendor:product:1.0:*:*:*:*:*:*:*")
	if !c.IsAnyPart() {
		t.Fatal("expected any part")
	}
	c2, _ := Parse("cpe:/a:vendor:product:1.0")
	if c2.IsAnyPart() {
		t.Fatal("did not expect any part")
	}
}
