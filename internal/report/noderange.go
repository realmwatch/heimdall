// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"strconv"
	"strings"
)

// NodeRange is a Node.js requirement (.nvmrc, .node-version or
// package.json engines.node) judged by major alone: what a host can
// offer a site is a major, and the patch release is the install's job.
type NodeRange struct {
	alts [][]nodeCmp // any alternative; each needs all its comparators
}

type nodeCmp struct {
	op    string // "=", ">=", ">", "<=", "<"
	major int
	exact bool // the version named more than a major (">20.1", "<20.5")
}

// ParseNodeRange parses the common forms: a version or major ("22",
// "v22.11.0", "22.x"), ^, ~, =, comparators, hyphen ranges, * and "||"
// alternatives. ok is false for names (lts/*, node, iron) and anything
// else it can't judge.
func ParseNodeRange(s string) (r NodeRange, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return r, false
	}
	for alt := range strings.SplitSeq(s, "||") {
		f := strings.Fields(alt)
		var cmps []nodeCmp
		for i := 0; i < len(f); i++ {
			if i+2 < len(f) && f[i+1] == "-" { // "18 - 20"
				lo, ok1 := parseNodeVer(f[i])
				hi, ok2 := parseNodeVer(f[i+2])
				if !ok1 || !ok2 {
					return r, false
				}
				cmps = append(cmps, nodeCmp{op: ">=", major: lo}, nodeCmp{op: "<=", major: hi})
				i += 2
				continue
			}
			c, ok := parseNodeCmp(f[i])
			if !ok {
				return r, false
			}
			if c.op != "" {
				cmps = append(cmps, c)
			}
		}
		if len(f) == 0 {
			return r, false
		}
		r.alts = append(r.alts, cmps)
	}
	return r, true
}

func parseNodeCmp(t string) (nodeCmp, bool) {
	if t == "*" || t == "x" || t == "X" {
		return nodeCmp{}, true // anything
	}
	for _, op := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
		if rest, ok := strings.CutPrefix(t, op); ok {
			m, ok := parseNodeVer(rest)
			if !ok {
				return nodeCmp{}, false
			}
			exact := strings.Count(strings.Trim(rest, "v"), ".") > 0 && !allZeroRest(rest)
			switch op {
			case "^", "~", "=":
				op = "="
			}
			return nodeCmp{op: op, major: m, exact: exact}, true
		}
	}
	m, ok := parseNodeVer(t)
	return nodeCmp{op: "=", major: m}, ok
}

// parseNodeVer is the major of "22", "v22.11.0", "22.x" or "22.*".
func parseNodeVer(t string) (int, bool) {
	t = strings.TrimPrefix(strings.TrimPrefix(t, "v"), "V")
	m, rest, _ := strings.Cut(t, ".")
	n, err := strconv.Atoi(m)
	if err != nil || n <= 0 || n > 999 {
		return 0, false
	}
	for p := range strings.SplitSeq(rest, ".") {
		if p == "" && rest == "" {
			break
		}
		if p != "x" && p != "X" && p != "*" {
			if _, err := strconv.Atoi(p); err != nil {
				return 0, false
			}
		}
	}
	return n, true
}

func allZeroRest(v string) bool {
	_, rest, _ := strings.Cut(strings.TrimPrefix(v, "v"), ".")
	return strings.Trim(rest, "0.") == ""
}

// Allows reports whether some release of major m meets the range.
func (r NodeRange) Allows(m int) bool {
	for _, alt := range r.alts {
		ok := true
		for _, c := range alt {
			switch c.op {
			case "=":
				ok = ok && m == c.major
			case ">=":
				ok = ok && m >= c.major
			case ">":
				ok = ok && (m > c.major || (c.exact && m == c.major))
			case "<=":
				ok = ok && m <= c.major
			case "<":
				ok = ok && (m < c.major || (c.exact && m == c.major))
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Major is the one major the range names (a version, ^, ~ or =, with no
// alternatives), or 0.
func (r NodeRange) Major() int {
	if len(r.alts) != 1 || len(r.alts[0]) != 1 || r.alts[0][0].op != "=" {
		return 0
	}
	return r.alts[0][0].major
}
