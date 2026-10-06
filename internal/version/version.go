package version

import "strings"

type Order int

const (
	Less Order = iota
	Equal
	Greater
	Uncertain
)

type component struct {
	num  string
	qual string
}

func Compare(a, b string) Order {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return Uncertain
	}
	as := splitVersion(a)
	bs := splitVersion(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ca, cb component
		if i < len(as) {
			ca = as[i]
		}
		if i < len(bs) {
			cb = bs[i]
		}
		if c := compareNumeric(ca.num, cb.num); c != 0 {
			return orderFromInt(c)
		}
		if c := compareQual(ca.qual, cb.qual); c != Equal {
			return c
		}
	}
	return Equal
}

func splitVersion(s string) []component {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '.', '-', '_', '+', '~':
			return true
		}
		return false
	})
	comps := make([]component, 0, len(parts))
	for _, p := range parts {
		comps = append(comps, parseComponent(p))
	}
	return comps
}

func parseComponent(p string) component {
	i := 0
	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	return component{num: p[:i], qual: p[i:]}
}

func compareNumeric(a, b string) int {
	a = trimZeros(a)
	b = trimZeros(b)
	if a == b {
		return 0
	}
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	if a < b {
		return -1
	}
	return 1
}

func trimZeros(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

var qualRanks = map[string]int{
	"dev":         -6,
	"alpha":       -5,
	"a":           -5,
	"beta":        -4,
	"b":           -4,
	"milestone":   -3,
	"m":           -3,
	"rc":          -2,
	"cr":          -2,
	"preview":     -1,
	"pre":         -1,
	"snapshot":    -1,
	"":            0,
	"p":           1,
	"patch":       1,
	"sp":          1,
	"servicepack": 1,
	"ga":          2,
	"final":       2,
	"release":     2,
}

func compareQual(a, b string) Order {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	if a == b {
		return Equal
	}
	al, an := splitQual(a)
	bl, bn := splitQual(b)
	ar, aok := qualRanks[al]
	br, bok := qualRanks[bl]
	if aok && bok {
		if ar != br {
			return orderFromInt(sign(ar - br))
		}
		if al != bl {
			return orderFromInt(lexCompare(al, bl))
		}
		return orderFromInt(compareNumeric(an, bn))
	}
	if !aok && !bok {
		if al != bl {
			return Uncertain
		}
		return orderFromInt(compareNumeric(an, bn))
	}
	return Uncertain
}

func splitQual(s string) (letters, num string) {
	i := 0
	for i < len(s) && isLetter(s[i]) {
		i++
	}
	letters = s[:i]
	rest := s[i:]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	return letters, rest[:j]
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}

func lexCompare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func orderFromInt(c int) Order {
	switch {
	case c < 0:
		return Less
	case c > 0:
		return Greater
	default:
		return Equal
	}
}
