// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nginx reads nginx.org's security advisories: the source of truth
// for nginx itself, published the day a fix ships, often days before the
// distros publish theirs. Heimdall matches them against nginx.org's own
// builds (whose versions distro advisories can't judge) and, until the
// distro publishes its own record, against the distro's builds too.
//
// The list comes from the XML nginx.org's page is generated from. It is
// untrusted input: malformed entries are skipped, text is cleaned and
// length-capped.
package nginx

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/realmwatch/heimdall/internal/netx"
)

// DefaultURL is the advisory list's source, in nginx.org's site repository.
const DefaultURL = "https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml"

// PageURL is the list as nginx.org publishes it, for people.
const PageURL = "https://nginx.org/en/security_advisories.html"

// Ecosystem and Package name nginx.org's ranges in the advisory records
// Heimdall stores: upstream versions ("1.30.7"), not any distro's.
const (
	Ecosystem = "nginx"
	Package   = "nginx"
)

// IDPrefix starts every advisory ID made here ("NGINX-CVE-2026-123007"),
// keeping them apart from OSV's.
const IDPrefix = "NGINX-"

// maxBytes caps the download; the real list is about 20 KB.
const maxBytes = 2 << 20

// maxItems caps how many advisories one list may carry.
const maxItems = 2000

const maxName = 200

// Advisory is one entry of nginx.org's list.
type Advisory struct {
	ID       string // IDPrefix + CVE
	CVE      string // "CVE-2026-123007"
	Name     string // "Memory corruption in HTTP/2 flow control"
	Severity string // Heimdall's rating: high, medium or low
	URL      string // the vendor advisory, when it has one
	// Vulnerable are inclusive version bounds ({"1.9.5", "1.31.8"}).
	Vulnerable [][2]string
	// Good are the first fixed version per branch ("1.31.9", "1.30.7").
	Good []string
	// Feature is the part of nginx the flaw is in, when it's one the
	// collector can tell is configured: http2, http3, mail, resolver,
	// proxy_protocol or mp4. "" otherwise.
	Feature string
}

// Fetch downloads and parses the list from url (DefaultURL if empty).
func Fetch(ctx context.Context, c *netx.Client, url string) ([]Advisory, error) {
	if url == "" {
		url = DefaultURL
	}
	raw, _, err := c.Get(ctx, url, maxBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("nginx advisories: %w", err)
	}
	list, _, err := Parse(raw)
	return list, err
}

var (
	cveRe  = regexp.MustCompile(`^(?:CVE-)?(\d{4}-\d{4,7})$`)
	verRe  = regexp.MustCompile(`^\d{1,4}(\.\d{1,6}){1,3}$`)
	httpRe = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?$`)
)

// Parse reads the advisory list. Entries without a CVE, rated "none"
// (nginx.org's own "not a vulnerability"), only for nginx/Windows, or with
// bounds it can't read are skipped; skipped says how many.
func Parse(raw []byte) (list []Advisory, skipped int, err error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = false
	d.Entity = xml.HTMLEntity
	seen := map[string]bool{}
	items := 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("nginx advisories: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "item" {
			continue
		}
		if items++; items > maxItems {
			return nil, 0, fmt.Errorf("nginx advisories: more than %d entries", maxItems)
		}
		attr := map[string]string{}
		for _, a := range se.Attr {
			attr[a.Name.Local] = a.Value
		}
		a, ok := parseItem(attr)
		if !ok || seen[a.ID] {
			skipped++
			continue
		}
		seen[a.ID] = true
		list = append(list, a)
	}
	if items == 0 {
		return nil, 0, errors.New("nginx advisories: no entries (not the advisory list?)")
	}
	return list, skipped, nil
}

func parseItem(attr map[string]string) (Advisory, bool) {
	m := cveRe.FindStringSubmatch(strings.TrimSpace(attr["cve"]))
	if m == nil {
		return Advisory{}, false
	}
	sev := rating(attr["severity"])
	if sev == "" {
		return Advisory{}, false
	}
	a := Advisory{CVE: "CVE-" + m[1], Severity: sev, Name: clean(attr["name"])}
	a.ID = IDPrefix + a.CVE
	if u := strings.TrimSpace(attr["advisory"]); httpRe.MatchString(u) && len(u) <= 300 {
		a.URL = u
	}
	vuln := strings.TrimSpace(attr["vulnerable"])
	if strings.Contains(vuln, "Windows") || vuln == "" {
		return Advisory{}, false
	}
	for part := range strings.SplitSeq(vuln, ",") {
		part = strings.TrimSpace(part)
		if part == "all" {
			a.Vulnerable = append(a.Vulnerable, [2]string{"0", ""})
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			hi = lo
		}
		if !verRe.MatchString(lo) || !verRe.MatchString(hi) || cmp(lo, hi) > 0 {
			return Advisory{}, false
		}
		a.Vulnerable = append(a.Vulnerable, [2]string{lo, hi})
	}
	if good := strings.TrimSpace(attr["good"]); good != "none" {
		for g := range strings.SplitSeq(good, ",") {
			g = strings.TrimSuffix(strings.TrimSpace(g), "+")
			if !verRe.MatchString(g) {
				return Advisory{}, false
			}
			a.Good = append(a.Good, g)
		}
	}
	slices.SortFunc(a.Good, cmp)
	a.Feature = feature(a.Name)
	return a, true
}

// rating maps nginx.org's severity to Heimdall's; "" for "none" or unknown.
func rating(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "major", "high":
		return "high"
	case "medium":
		return "medium"
	case "minor", "low":
		return "low"
	}
	return ""
}

// feature names the configurable part of nginx an advisory's title points
// at. The match is on nginx.org's wording, so it only ever adds context.
func feature(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "http/3") || strings.Contains(n, "ngx_http_v3_module"):
		return "http3"
	case strings.Contains(n, "http/2") && !strings.Contains(n, "proxy_module"):
		return "http2"
	case strings.Contains(n, "mail"):
		return "mail"
	case strings.Contains(n, "proxy protocol"):
		return "proxy_protocol"
	case strings.Contains(n, "mp4"):
		return "mp4"
	case strings.Contains(n, "resolver") && !strings.Contains(n, "ocsp"):
		return "resolver"
	}
	return ""
}

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxName {
		s = string(r[:maxName]) + "…"
	}
	return s
}

// Affects reports whether upstream version v ("1.30.6") is vulnerable:
// inside a vulnerable range, and not at or past its branch's fix (or past
// every fix).
func (a Advisory) Affects(v string) bool {
	if !verRe.MatchString(v) {
		return false
	}
	in := false
	for _, r := range a.Vulnerable {
		if cmp(v, r[0]) >= 0 && (r[1] == "" || cmp(v, r[1]) <= 0) {
			in = true
			break
		}
	}
	if !in {
		return false
	}
	if len(a.Good) == 0 {
		return true
	}
	if cmp(v, a.Good[len(a.Good)-1]) >= 0 {
		return false
	}
	for _, g := range a.Good {
		if branch(g) == branch(v) && cmp(v, g) >= 0 {
			return false
		}
	}
	return true
}

// FixFor is the version that fixes v: its own branch's fix when there is
// one, else the oldest fix newer than v. "" with none.
func (a Advisory) FixFor(v string) string {
	for _, g := range a.Good {
		if branch(g) == branch(v) && cmp(v, g) < 0 {
			return g
		}
	}
	for _, g := range a.Good {
		if cmp(v, g) < 0 {
			return g
		}
	}
	return ""
}

// OSV renders the advisory as an OSV record, so it is stored and shown
// like any other: its ranges are the vulnerable versions, cut at each
// branch's fix.
func (a Advisory) OSV() []byte {
	type event struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
	}
	type rng struct {
		Type   string  `json:"type"`
		Events []event `json:"events"`
	}
	var ranges []rng
	for _, iv := range a.intervals() {
		e := []event{{Introduced: iv.lo}}
		if iv.fixed != "" {
			e = append(e, event{Fixed: iv.fixed})
		} else if iv.last != "" {
			e = append(e, event{LastAffected: iv.last})
		}
		ranges = append(ranges, rng{Type: "ECOSYSTEM", Events: e})
	}
	refs := []map[string]string{{"type": "WEB", "url": PageURL}}
	if a.URL != "" {
		refs = append([]map[string]string{{"type": "ADVISORY", "url": a.URL}}, refs...)
	}
	rec := map[string]any{
		"schema_version": "1.6.0",
		"id":             a.ID,
		"aliases":        []string{a.CVE},
		"summary":        a.Name,
		"affected": []any{map[string]any{
			"package": map[string]string{"ecosystem": Ecosystem, "name": Package},
			"ranges":  ranges,
		}},
		"references":        refs,
		"database_specific": map[string]any{"severity": a.Severity, "source": "nginx.org", "good": a.Good, "feature": a.Feature},
	}
	b, _ := json.Marshal(rec) // plain maps and strings: can't fail
	return b
}

type interval struct{ lo, fixed, last string }

// intervals are the vulnerable versions as half-open ranges cut at each
// fix: below the oldest fix, and from each later branch's start to its fix.
func (a Advisory) intervals() []interval {
	// Versions not yet fixed, as [start, fix) pairs; the last one open
	// when nothing fixes it.
	var bad [][2]string
	start := "0"
	for _, g := range a.Good {
		if cmp(start, g) < 0 {
			bad = append(bad, [2]string{start, g})
		}
		start = nextBranch(g)
	}
	if len(a.Good) == 0 {
		bad = append(bad, [2]string{"0", ""})
	}
	var out []interval
	for _, v := range a.Vulnerable {
		for _, b := range bad {
			lo := v[0]
			if cmp(b[0], lo) > 0 {
				lo = b[0]
			}
			switch {
			case b[1] != "" && cmp(lo, b[1]) >= 0:
				continue
			case v[1] != "" && cmp(lo, v[1]) > 0:
				continue
			case v[1] == "" || (b[1] != "" && cmp(b[1], v[1]) <= 0):
				out = append(out, interval{lo: lo, fixed: b[1]})
			default: // the vulnerable range ends before the fix
				out = append(out, interval{lo: lo, last: v[1]})
			}
		}
	}
	return out
}

// UpstreamVersion is the nginx version a package version carries:
// "1.30.6-1~jammy", "1.18.0-6ubuntu14.4", "1:1.24.0-2", "1.20.1-14.el9_2.1"
// and "1.30.7-r0" give "1.30.6", "1.18.0", "1.24.0", "1.20.1", "1.30.7".
func UpstreamVersion(pkgVersion string) (string, bool) {
	v := pkgVersion
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.IndexAny(v, "-+~"); i >= 0 {
		v = v[:i]
	}
	return v, verRe.MatchString(v)
}

// nginxOrgBuild matches nginx.org's own package versions: "1.30.6-1~jammy"
// (deb), "1.30.6-1.el9.ngx" (rpm). Distro builds of nginx never look like
// either, so this tells nginx.org's builds apart even when the collector
// can't say where a package came from.
var nginxOrgBuild = regexp.MustCompile(`^(\d+:)?\d+(\.\d+)+-\d+(~[a-z]+|\.[a-z0-9_]+\.ngx)$`)

// IsNginxOrgBuild reports whether a package version is nginx.org's build.
func IsNginxOrgBuild(pkgVersion string) bool { return nginxOrgBuild.MatchString(pkgVersion) }

// IsSuryBuild reports whether a package version is Ondřej Surý's build
// ("1.26.3-1+ubuntu22.04.1+deb.sury.org+1"), from the ondrej/nginx PPA
// Laravel Forge used to install nginx from. Launchpad has removed that
// PPA, so no fixed version will come from it.
func IsSuryBuild(pkgVersion string) bool { return strings.Contains(pkgVersion, "deb.sury.org") }

// IsThirdPartyBuild reports whether a package version is a build of nginx
// that isn't a distro's: nginx.org's or Ondřej Surý's.
func IsThirdPartyBuild(pkgVersion string) bool {
	return IsNginxOrgBuild(pkgVersion) || IsSuryBuild(pkgVersion)
}

// branch is a version's major.minor ("1.30").
func branch(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// nextBranch is the first version of the branch after v's ("1.31.0").
func nextBranch(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	n, _ := strconv.Atoi(parts[1])
	return parts[0] + "." + strconv.Itoa(n+1) + ".0"
}

// cmp compares dotted numeric versions; missing parts count as 0.
func cmp(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Compare compares two upstream nginx versions (-1, 0, 1).
func Compare(a, b string) int { return cmp(a, b) }
