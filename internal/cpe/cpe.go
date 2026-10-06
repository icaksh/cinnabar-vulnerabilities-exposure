package cpe

import (
	"fmt"
	"strings"
)

type CPE struct {
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
	Raw       string
}

const (
	Any = "*"
	NA  = "-"
)

func Parse(raw string) (*CPE, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty cpe")
	}
	switch {
	case strings.HasPrefix(raw, "cpe:2.3:"):
		return parse23(raw)
	case strings.HasPrefix(raw, "cpe:/"):
		return parse22(raw)
	default:
		return nil, fmt.Errorf("unsupported cpe format: %q", raw)
	}
}

func parse23(raw string) (*CPE, error) {
	comps := splitComponents(raw)
	if len(comps) < 3 {
		return nil, fmt.Errorf("invalid cpe 2.3: %q", raw)
	}
	c := &CPE{Raw: raw}
	fill := func(i int) string {
		if i < len(comps) {
			return comps[i]
		}
		return Any
	}
	c.Part = normalizeEmpty(fill(2))
	c.Vendor = normalizeEmpty(fill(3))
	c.Product = normalizeEmpty(fill(4))
	c.Version = normalizeEmpty(fill(5))
	c.Update = normalizeEmpty(fill(6))
	c.Edition = normalizeEmpty(fill(7))
	c.Language = normalizeEmpty(fill(8))
	c.SWEdition = normalizeEmpty(fill(9))
	c.TargetSW = normalizeEmpty(fill(10))
	c.TargetHW = normalizeEmpty(fill(11))
	c.Other = normalizeEmpty(fill(12))
	return c, nil
}

func parse22(raw string) (*CPE, error) {
	comps := splitComponents(raw)
	if len(comps) < 2 {
		return nil, fmt.Errorf("invalid cpe 2.2: %q", raw)
	}
	c := &CPE{Raw: raw}
	fill := func(i int) string {
		if i < len(comps) {
			return comps[i]
		}
		return ""
	}
	part := fill(1)
	part = strings.TrimPrefix(part, "/")
	if part == "" {
		part = Any
	}
	c.Part = normalizeEmpty(part)
	c.Vendor = normalizeEmpty(fill(2))
	c.Product = normalizeEmpty(fill(3))
	c.Version = normalizeEmpty(fill(4))
	c.Update = normalizeEmpty(fill(5))
	c.Edition = normalizeEmpty(fill(6))
	c.Language = normalizeEmpty(fill(7))
	return c, nil
}

func normalizeEmpty(s string) string {
	if s == "" {
		return Any
	}
	return s
}

func splitComponents(s string) []string {
	var comps []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			comps = append(comps, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	comps = append(comps, cur.String())
	return comps
}

func (c *CPE) PartLower() string    { return strings.ToLower(c.Part) }
func (c *CPE) VendorLower() string  { return strings.ToLower(c.Vendor) }
func (c *CPE) ProductLower() string { return strings.ToLower(c.Product) }

func (c *CPE) IsAnyPart() bool {
	p := c.PartLower()
	return p == Any || p == NA || p == ""
}

func (c *CPE) HasVersion() bool {
	v := c.Version
	if v == "" || v == Any || v == NA {
		return false
	}
	return true
}

func (c *CPE) VersionValue() string {
	if !c.HasVersion() {
		return ""
	}
	return c.Version
}
