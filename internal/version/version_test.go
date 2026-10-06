package version

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want Order
	}{
		{"1.2.0", "1.2.0", Equal},
		{"1.2.0", "1.2.1", Less},
		{"1.2.1", "1.2.0", Greater},
		{"1.24.2", "1.3.0", Greater},
		{"10.2", "2.4.58", Greater},
		{"2.4.58", "10.2", Less},
		{"1.31.6", "1.31.5", Greater},
		{"9.6p1", "9.6p2", Less},
		{"9.6p2", "9.6p1", Greater},
		{"9.6p1", "9.6", Greater},
		{"9.6", "9.6p1", Less},
		{"8.9p1", "9.6p1", Less},
		{"1.0", "1.0.1", Less},
		{"1.0.1", "1.0", Greater},
		{"1.0", "1.0a", Greater},
		{"1.0a", "1.0", Less},
		{"1.0alpha", "1.0beta", Less},
		{"1.0rc1", "1.0rc2", Less},
		{"1.0rc2", "1.0", Less},
		{"1.0", "1.0rc2", Greater},
		{"1.10", "1.2", Greater},
		{"1.02", "1.2", Equal},
		{"1.2.3.4.5", "1.2.3.4.4", Greater},
		{"1.0-sp1", "1.0", Greater},
		{"1.0", "1.0-sp1", Less},
	}
	for _, c := range cases {
		got := Compare(c.a, c.b)
		if got != c.want {
			t.Errorf("Compare(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareUncertain(t *testing.T) {
	cases := []struct{ a, b string }{
		{"", "1.0"},
		{"1.0", ""},
		{"   ", "1.0"},
		{"1.0u1", "1.0"},
		{"1.0", "1.0u1"},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != Uncertain {
			t.Errorf("Compare(%q, %q) = %v, want Uncertain", c.a, c.b, got)
		}
	}
}

func TestCompareSameLetters(t *testing.T) {
	if got := Compare("1.0p1", "1.0p2"); got != Less {
		t.Errorf("Compare(1.0p1, 1.0p2) = %v, want Less", got)
	}
	if got := Compare("1.0u2", "1.0u1"); got != Greater {
		t.Errorf("Compare(1.0u2, 1.0u1) = %v, want Greater", got)
	}
}

func TestBoundaryRange(t *testing.T) {
	lo := "1.2.0"
	hi := "1.4.0"
	check := func(v string, want Order) {
		if got := Compare(v, lo); got != want {
			t.Errorf("Compare(%q, %q) = %v, want %v", v, lo, got, want)
		}
	}
	check("1.1.9", Less)
	check("1.2.0", Equal)
	check("1.3.9", Greater)
	check("1.4.0", Greater)
	if got := Compare("1.4.0", hi); got != Equal {
		t.Errorf("Compare(1.4.0, 1.4.0) = %v, want Equal", got)
	}
	if got := Compare("1.3.9", hi); got != Less {
		t.Errorf("Compare(1.3.9, 1.4.0) = %v, want Less", got)
	}
}
