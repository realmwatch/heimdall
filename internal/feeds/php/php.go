// SPDX-License-Identifier: AGPL-3.0-or-later

// Package php reads the PHP project's own security advisories: the ones
// published on php-src's GitHub repository the day a release fixes them,
// hours or days before any other database has them. Heimdall matches them
// against third-party PHP builds (Ondřej Surý's, mainly), whose versions
// the distro's advisories can't judge.
//
// Each advisory lists, per branch, the versions affected and the release
// that fixes them, and names the part of PHP the flaw is in ("sapi-fpm",
// "ext-soap"), so a host is only flagged when that part is installed.
//
// The list comes from GitHub's REST API. It is untrusted input: entries
// that don't parse are skipped, text is cleaned and length-capped.
package php

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/realmwatch/heimdall/internal/netx"
)

// DefaultURL lists php-src's published advisories, a page at a time.
const DefaultURL = "https://api.github.com/repos/php/php-src/security-advisories?state=published&per_page=100"

// PageURL is where people read the advisories.
const PageURL = "https://github.com/php/php-src/security/advisories"

// Ecosystem and Package name the ranges in the advisory records Heimdall
// stores: upstream PHP versions ("8.4.28"), not any distro's.
const (
	Ecosystem = "PHP"
	Package   = "php"
)

// IDPrefix starts every advisory ID made here ("PHP-GHSA-gr4f-wgx5-jpfv"),
// keeping them apart from OSV's.
const IDPrefix = "PHP-"

const (
	maxPageBytes = 8 << 20 // a full page of 100 is about 1 MB
	maxPages     = 20
	maxItems     = 2000
	maxSummary   = 200
	maxRanges    = 40
)

// Advisory is one of php-src's advisories.
type Advisory struct {
	ID                 string // IDPrefix + GHSA
	GHSA               string // "GHSA-gr4f-wgx5-jpfv"
	CVE                string // "CVE-2026-129496", or "" when it has none
	Summary            string
	Severity           string // critical, high, medium or low
	URL                string // the advisory's page
	CVSSv3             string // vectors, when given
	CVSSv4             string
	Published, Updated string
	// Ranges are the affected versions: each [lo, hi], lo "" from the
	// start, hi "" open-ended; HiIncl says whether hi itself is affected.
	Ranges []Range
	// Good are the versions that fix it, one per branch at most, sorted.
	Good []string
	// Components are the parts of PHP it's in ("sapi-fpm", "ext-soap");
	// empty when it doesn't say, which counts as PHP's core.
	Components []string
}

// Range is one span of affected versions.
type Range struct {
	Lo, Hi string
	HiIncl bool
}

// Fetch downloads every page of the list from url (DefaultURL if empty).
// token, when set, is a GitHub token: it only raises the rate limit.
func Fetch(ctx context.Context, c *netx.Client, url, token string) ([]Advisory, error) {
	if url == "" {
		url = DefaultURL
	}
	h := http.Header{}
	h.Set("Accept", "application/vnd.github+json")
	h.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	var list []Advisory
	seen := map[string]bool{}
	for page := 0; url != ""; page++ {
		if page == maxPages {
			return nil, fmt.Errorf("php advisories: more than %d pages", maxPages)
		}
		raw, resp, err := c.Get(ctx, url, maxPageBytes, h)
		if err != nil {
			return nil, fmt.Errorf("php advisories: %w", err)
		}
		items, _, err := Parse(raw)
		if err != nil {
			return nil, err
		}
		for _, a := range items {
			if !seen[a.ID] {
				seen[a.ID] = true
				list = append(list, a)
			}
		}
		if len(list) > maxItems {
			return nil, fmt.Errorf("php advisories: more than %d entries", maxItems)
		}
		url = nextLink(resp.Get("Link"), url)
	}
	if len(list) == 0 {
		return nil, errors.New("php advisories: none listed (not the advisory list?)")
	}
	return list, nil
}

var linkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink is the Link header's next page, kept on the same host and path
// as the page it came from.
func nextLink(header, from string) string {
	m := linkRe.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	base, _, _ := strings.Cut(from, "?")
	next, _, _ := strings.Cut(m[1], "?")
	if next != base {
		return ""
	}
	return m[1]
}

type apiAdvisory struct {
	GHSA         string  `json:"ghsa_id"`
	CVE          *string `json:"cve_id"`
	HTMLURL      string  `json:"html_url"`
	Summary      string  `json:"summary"`
	Severity     string  `json:"severity"`
	State        string  `json:"state"`
	Published    *string `json:"published_at"`
	Updated      *string `json:"updated_at"`
	Withdrawn    *string `json:"withdrawn_at"`
	CVSSSeverity struct {
		V3 struct {
			Vector *string `json:"vector_string"`
		} `json:"cvss_v3"`
		V4 struct {
			Vector *string `json:"vector_string"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Vulnerabilities []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Range   *string `json:"vulnerable_version_range"`
		Patched *string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

var (
	ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	cveRe  = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	verRe  = regexp.MustCompile(`^\d{1,3}(\.\d{1,5}){1,3}$`)
	timeRe = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)
	cvssRe = regexp.MustCompile(`^CVSS:[34]\.[01]/[A-Za-z:/]{1,200}$`)
	compRe = regexp.MustCompile(`^(sapi|ext)-[a-z0-9_]{1,32}$`)
)

// Parse reads one page of the list. Advisories that are withdrawn, not
// published, or without a range it can read are skipped; skipped says how
// many.
func Parse(raw []byte) (list []Advisory, skipped int, err error) {
	var items []apiAdvisory
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, 0, fmt.Errorf("php advisories: %w", err)
	}
	if len(items) > maxItems {
		return nil, 0, fmt.Errorf("php advisories: more than %d entries", maxItems)
	}
	for _, it := range items {
		a, ok := parseItem(it)
		if !ok {
			skipped++
			continue
		}
		list = append(list, a)
	}
	return list, skipped, nil
}

func parseItem(it apiAdvisory) (Advisory, bool) {
	if !ghsaRe.MatchString(it.GHSA) || (it.State != "" && it.State != "published") || it.Withdrawn != nil {
		return Advisory{}, false
	}
	a := Advisory{ID: IDPrefix + it.GHSA, GHSA: it.GHSA, Summary: clean(it.Summary),
		URL: PageURL + "/" + it.GHSA}
	if it.CVE != nil && cveRe.MatchString(*it.CVE) {
		a.CVE = *it.CVE
	}
	switch s := strings.ToLower(strings.TrimSpace(it.Severity)); s {
	case "critical", "high", "medium", "low":
		a.Severity = s
	}
	if v := it.CVSSSeverity.V3.Vector; v != nil && cvssRe.MatchString(*v) {
		a.CVSSv3 = *v
	}
	if v := it.CVSSSeverity.V4.Vector; v != nil && cvssRe.MatchString(*v) {
		a.CVSSv4 = *v
	}
	if it.Published != nil && timeRe.MatchString(*it.Published) {
		a.Published = *it.Published
	}
	if it.Updated != nil && timeRe.MatchString(*it.Updated) {
		a.Updated = *it.Updated
	}
	for _, v := range it.Vulnerabilities {
		if v.Range == nil {
			continue
		}
		ranges, ok := parseRange(*v.Range)
		if !ok {
			continue
		}
		good := []string{}
		if v.Patched != nil {
			good = parseVersions(*v.Patched)
		}
		// "< 8.4.28" says 8.4.28 fixes it even where patched_versions is
		// empty.
		for _, r := range ranges {
			if r.Hi != "" && !r.HiIncl {
				good = append(good, r.Hi)
			}
		}
		a.Ranges = append(a.Ranges, ranges...)
		for _, g := range good {
			if !slices.Contains(a.Good, g) {
				a.Good = append(a.Good, g)
			}
		}
		if c := Component(v.Package.Name); c != "" && !slices.Contains(a.Components, c) {
			a.Components = append(a.Components, c)
		} else if c == "" {
			a.Components = append(a.Components, "")
		}
	}
	if len(a.Ranges) == 0 || len(a.Ranges) > maxRanges {
		return Advisory{}, false
	}
	slices.SortFunc(a.Good, cmp)
	// One entry without a component means the core: it applies wherever
	// PHP is installed.
	if slices.Contains(a.Components, "") {
		a.Components = nil
	}
	slices.Sort(a.Components)
	return a, true
}

// Component normalizes an advisory's package name to the part of PHP it
// names ("PHP-FPM" → "sapi-fpm"), or "" for the core or a name it can't
// place.
func Component(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "php-fpm", "fpm":
		return "sapi-fpm"
	case "php-cgi", "cgi":
		return "sapi-cgi"
	}
	if compRe.MatchString(n) {
		return n
	}
	return ""
}

// parseRange reads a vulnerable_version_range: ">= 8.2.7, < 8.2.36",
// "< 8.2.36", ">= 8.1.20, <= 8.1.34", "> 8.1.0, < 8.1.3", "8.0.0 - 8.0.9,
// 8.1.0 - 8.1.2" or a single version.
func parseRange(s string) ([]Range, bool) {
	var out []Range
	var cur *Range
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, " - "); ok {
			lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
			if !verRe.MatchString(lo) || !verRe.MatchString(hi) || cmp(lo, hi) > 0 {
				return nil, false
			}
			out = append(out, Range{Lo: lo, Hi: hi, HiIncl: true})
			cur = nil
			continue
		}
		op, v := splitOp(part)
		if !verRe.MatchString(v) {
			return nil, false
		}
		switch op {
		case ">=", ">":
			if op == ">" {
				v = nextPatch(v)
			}
			out = append(out, Range{Lo: v})
			cur = &out[len(out)-1]
		case "<", "<=":
			if cur == nil || cur.Hi != "" {
				out = append(out, Range{})
				cur = &out[len(out)-1]
			}
			cur.Hi, cur.HiIncl = v, op == "<="
			if cur.Lo != "" && cmp(cur.Lo, cur.Hi) > 0 {
				return nil, false
			}
			cur = nil
		case "=", "":
			out = append(out, Range{Lo: v, Hi: v, HiIncl: true})
			cur = nil
		default:
			return nil, false
		}
	}
	return out, len(out) > 0
}

func splitOp(s string) (op, v string) {
	for _, o := range []string{">=", "<=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(s, o); ok {
			return o, strings.TrimSpace(rest)
		}
	}
	return "", s
}

// parseVersions reads patched_versions: "8.2.36", "8.1.3, 8.0.16, 7.4.28",
// "None" or "".
func parseVersions(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		v = strings.TrimSpace(v)
		if verRe.MatchString(v) {
			out = append(out, v)
		}
	}
	return out
}

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxSummary {
		s = string(r[:maxSummary]) + "…"
	}
	return s
}

// Affects reports whether upstream version v ("8.4.27") is vulnerable:
// inside an affected range, and not at or past its own branch's fix.
func Affects(ranges []Range, good []string, v string) bool {
	if !verRe.MatchString(v) {
		return false
	}
	for _, g := range good {
		if branch(g) == branch(v) && cmp(v, g) >= 0 {
			return false
		}
	}
	for _, r := range ranges {
		if r.Lo != "" && cmp(v, r.Lo) < 0 {
			continue
		}
		if r.Hi == "" || cmp(v, r.Hi) < 0 || (r.HiIncl && cmp(v, r.Hi) == 0) {
			return true
		}
	}
	return false
}

// FixFor is the release on v's own branch that fixes it, or "" when the
// branch has none (a branch past its end of life, say): a fix on another
// branch isn't an update apt will offer.
func FixFor(good []string, v string) string {
	for _, g := range good {
		if branch(g) == branch(v) && cmp(v, g) < 0 {
			return g
		}
	}
	return ""
}

// Affects reports whether the advisory affects upstream version v.
func (a Advisory) Affects(v string) bool { return Affects(a.Ranges, a.Good, v) }

// OSV renders the advisory as an OSV record, so it is stored and shown
// like any other.
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
	ranges := make([]rng, 0, len(a.Ranges))
	for _, r := range a.Ranges {
		lo := r.Lo
		if lo == "" {
			lo = "0"
		}
		e := []event{{Introduced: lo}}
		switch {
		case r.Hi != "" && r.HiIncl:
			e = append(e, event{LastAffected: r.Hi})
		case r.Hi != "":
			e = append(e, event{Fixed: r.Hi})
		}
		ranges = append(ranges, rng{Type: "ECOSYSTEM", Events: e})
	}
	aliases := []string{a.GHSA}
	if a.CVE != "" {
		aliases = []string{a.CVE, a.GHSA}
	}
	var sev []map[string]string
	if a.CVSSv3 != "" {
		sev = append(sev, map[string]string{"type": "CVSS_V3", "score": a.CVSSv3})
	}
	if a.CVSSv4 != "" {
		sev = append(sev, map[string]string{"type": "CVSS_V4", "score": a.CVSSv4})
	}
	rec := map[string]any{
		"schema_version": "1.6.0",
		"id":             a.ID,
		"aliases":        aliases,
		"summary":        a.Summary,
		"affected": []any{map[string]any{
			"package": map[string]string{"ecosystem": Ecosystem, "name": Package},
			"ranges":  ranges,
		}},
		"references": []map[string]string{{"type": "ADVISORY", "url": a.URL}},
		"database_specific": map[string]any{"severity": a.Severity, "source": "php-src", "good": a.Good,
			"components": a.Components},
	}
	if sev != nil {
		rec["severity"] = sev
	}
	if a.Published != "" {
		rec["published"] = a.Published
	}
	if a.Updated != "" {
		rec["modified"] = a.Updated
	}
	b, _ := json.Marshal(rec) // plain maps and strings: can't fail
	return b
}

// UpstreamVersion is the PHP version a package version carries:
// "8.4.27-1+ubuntu24.04.1+deb.sury.org+1", "1:8.3.6-0ubuntu0.24.04.5" and
// "8.5.12-3+0~deb.sury.org.1+ubuntu26.04" give "8.4.27", "8.3.6", "8.5.12".
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

// sourceRe matches PHP's per-branch source package names ("php8.4").
var sourceRe = regexp.MustCompile(`^php(\d)\.(\d{1,2})$`)

// IsSource reports whether a source package is a build of PHP itself.
func IsSource(name string) bool { return sourceRe.MatchString(name) }

// suryDebian matches Ondřej Surý's Debian builds
// ("8.2.12-1+0~20231026.31+debian12~1.gbp3fb5e2").
var suryDebian = regexp.MustCompile(`\+0~\d{8}\.\d+\+debian\d+~1\.gbp[0-9a-f]+$`)

// IsSuryBuild reports whether a package version is Ondřej Surý's build:
// "8.4.27-1+ubuntu24.04.1+deb.sury.org+1" on Ubuntu, or his Debian
// repository's "+debian12~1.gbp…" versions.
func IsSuryBuild(pkgVersion string) bool {
	return strings.Contains(pkgVersion, "deb.sury.org") || suryDebian.MatchString(pkgVersion)
}

// extPackages maps extensions to the Debian binary package (after
// "php8.4-") that ships them; any other extension is in the core packages
// (php8.4-common and the SAPIs) and installed wherever PHP is.
var extPackages = map[string]string{
	"soap": "soap", "dom": "xml", "xml": "xml", "simplexml": "xml", "xmlreader": "xml",
	"xmlwriter": "xml", "xsl": "xml", "curl": "curl", "gd": "gd", "intl": "intl",
	"mbstring": "mbstring", "mysqlnd": "mysql", "mysqli": "mysql", "pdo_mysql": "mysql",
	"pgsql": "pgsql", "pdo_pgsql": "pgsql", "sqlite3": "sqlite3", "pdo_sqlite": "sqlite3",
	"ldap": "ldap", "zip": "zip", "bcmath": "bcmath", "imap": "imap", "opcache": "opcache",
	"readline": "readline", "snmp": "snmp", "tidy": "tidy", "odbc": "odbc", "pdo_odbc": "odbc",
	"dba": "dba", "enchant": "enchant", "gmp": "gmp", "bz2": "bz2", "pdo_firebird": "interbase",
	"interbase": "interbase", "pspell": "pspell",
}

// Installed reports whether any of components is installed, given the
// binary packages built from source ("php8.4"). No components means the
// core, always installed.
func Installed(components []string, source string, binaries []string) bool {
	if len(components) == 0 {
		return true
	}
	for _, c := range components {
		pkg, ok := componentPackage(c, source)
		if !ok || slices.Contains(binaries, pkg) {
			return true
		}
	}
	return false
}

// componentPackage is the binary package a component ships in; ok is
// false when it's in the core packages.
func componentPackage(c, source string) (string, bool) {
	kind, name, _ := strings.Cut(c, "-")
	if kind == "sapi" {
		switch name {
		case "fpm", "cgi", "cli", "phpdbg":
			return source + "-" + name, true
		case "apache2handler", "apache2", "apache":
			return "libapache2-mod-" + source, true
		case "embed":
			return "lib" + source + "-embed", true
		}
		return "", false
	}
	if pkg, ok := extPackages[name]; ok {
		return source + "-" + pkg, true
	}
	return "", false
}

// branch is a version's major.minor ("8.4").
func branch(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// nextPatch is the version right after v ("8.1.0" → "8.1.1").
func nextPatch(v string) string {
	parts := strings.Split(v, ".")
	n, _ := strconv.Atoi(parts[len(parts)-1])
	parts[len(parts)-1] = strconv.Itoa(n + 1)
	return strings.Join(parts, ".")
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
