// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/feeds/news"
	"github.com/realmwatch/heimdall/internal/store"
)

// ── Threat news ────────────────────────────────────────────────────────────

// newsCap is how many incidents the News page lists.
const newsCap = 200

type newsBody struct {
	Items      []newsRow
	Total      int // incidents before filtering
	Affecting  int // incidents that affect a visible host
	Filter     string
	Categories []newsChip
	More       int // incidents past newsCap
	ShowOrgs   bool
	Sources    []newsSourceRow
	Query      string // the search box, as typed
}

// newsQueryMax caps the news search box.
const newsQueryMax = 200

// matchesNews reports whether every word of the search appears somewhere
// in the item: its title, summary, product, CVEs, tags, where it's from or
// the hosts it affects. Plain substring matching, ignoring case.
func matchesNews(r newsRow, words []string) bool {
	var b strings.Builder
	for _, s := range []string{r.Title, r.Summary, r.Product, r.Category, r.CategoryLabel(), r.Via} {
		b.WriteString(strings.ToLower(s))
		b.WriteByte('\n')
	}
	for _, l := range [][]string{r.CVEs, r.Tags, r.Stacks, r.Affected, r.Fixed} {
		for _, s := range l {
			b.WriteString(strings.ToLower(s))
			b.WriteByte('\n')
		}
	}
	for _, a := range r.Also {
		b.WriteString(a.Via + "\n")
	}
	for _, h := range r.Hosts {
		b.WriteString(strings.ToLower(h.Name) + "\n")
	}
	hay := b.String()
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// newsQuietAfter is how long a source may go without publishing before
// the News page says so: a silent source otherwise looks like a calm week.
const newsQuietAfter = 3 * 24 * time.Hour

// newsSourceRow is a configured source as the News page lists it.
type newsSourceRow struct {
	Name      string
	URL       string
	Published *time.Time // nil: not known yet
	Checked   *time.Time // nil: never fetched
	Quiet     bool       // nothing published for newsQuietAfter
}

type newsChip struct {
	Slug, Label string
	Count       int
}

// newsRow is an incident as the UI shows it. Every string in it comes from
// the feed and is rendered as escaped text only.
type newsRow struct {
	store.NewsEntry
	Via  string     // the item's site, for attribution
	Also []newsLink // articles elsewhere about the same CVEs, folded into this one
}

type newsLink struct{ Via, URL string }

var categoryLabels = map[string]string{"patch": "Patches", "breach": "Breaches", "supply-chain": "Supply chain"}

// Started and Closed are pointers for the date template funcs.
func (r newsRow) Started() *time.Time { t := r.StartedAt; return &t }
func (r newsRow) Closed() *time.Time  { return r.ClosedAt }

// CategoryLabel names the incident's category for a pill.
func (r newsRow) CategoryLabel() string {
	return map[string]string{"patch": "patch", "breach": "breach", "supply-chain": "supply chain"}[r.Category]
}

// Patch returns the pill class and label for the patch status (fixed
// strings only, never feed text).
func (r newsRow) Patch() (p struct{ Class, Label string }) {
	switch r.PatchStatus {
	case "patched":
		p.Class, p.Label = "ok", "patch available"
	case "partial":
		p.Class, p.Label = "warn", "partly patched"
	case "unpatched":
		p.Class, p.Label = "bad", "no patch yet"
	case "no-fix-needed":
		p.Class, p.Label = "muted", "no fix needed"
	}
	return p
}

// newsRows turns entries into rows, folding repeats: an article whose CVEs
// an incident (or a newer article) already names in full becomes an "also"
// link on that one, so a story covered by three sources is listed once.
// kinds maps each source to store.NewsIncidents or store.NewsArticles;
// a source missing from it counts as an incident list.
func newsRows(entries []store.NewsEntry, kinds map[string]string) []newsRow {
	covers := func(a, b []string) bool { // a names every CVE in b
		for _, c := range b {
			if !slices.Contains(a, c) {
				return false
			}
		}
		return true
	}
	into := make([]int, len(entries)) // the entry each one folds into, or -1
	for i := range into {
		into[i] = -1
	}
	for i, e := range entries {
		if kinds[e.Source] != store.NewsArticles || len(e.CVEs) == 0 {
			continue
		}
		for j, o := range entries {
			if j == i || into[j] != -1 || !covers(o.CVEs, e.CVEs) {
				continue
			}
			if kinds[o.Source] != store.NewsArticles || (j < i && len(o.CVEs) == len(e.CVEs)) {
				into[i] = j
				break
			}
		}
	}
	out := make([]newsRow, 0, len(entries))
	at := make([]int, len(entries))
	for i, e := range entries {
		if into[i] == -1 {
			at[i] = len(out)
			out = append(out, newsRow{NewsEntry: e, Via: itemSite(e)})
		}
	}
	for i, e := range entries {
		if j := into[i]; j != -1 {
			r := &out[at[j]]
			if !slices.ContainsFunc(r.Also, func(l newsLink) bool { return l.URL == e.URL }) {
				r.Also = append(r.Also, newsLink{Via: itemSite(e), URL: e.URL})
			}
		}
	}
	return out
}

// itemSite names where an item links to (thehackernews.com, not the
// feed proxy that serves its feed), falling back to the source's host.
func itemSite(e store.NewsEntry) string {
	if h := sourceHost(e.URL); h != "" {
		return h
	}
	return sourceHost(e.Source)
}

// newsKinds maps each fetched source to its kind.
func (s *server) newsKinds(ctx context.Context) (map[string]string, []store.NewsSource, error) {
	srcs, err := s.st.NewsSources(ctx)
	if err != nil {
		return nil, nil, err
	}
	kinds := map[string]string{}
	for _, ns := range srcs {
		kinds[ns.Source] = ns.Kind
	}
	return kinds, srcs, nil
}

// newsSourceRows lists the configured sources in config order with when
// each last published, naming each by the site its items link to.
func newsSourceRows(configured []string, fetched []store.NewsSource, entries []store.NewsEntry, now time.Time) []newsSourceRow {
	byURL := map[string]store.NewsSource{}
	for _, ns := range fetched {
		byURL[ns.Source] = ns
	}
	site := map[string]string{}
	for _, e := range entries {
		if _, ok := site[e.Source]; !ok {
			site[e.Source] = itemSite(e)
		}
	}
	var out []newsSourceRow
	for _, src := range configured {
		r := newsSourceRow{Name: site[src], URL: src}
		if r.Name == "" {
			r.Name = sourceHost(src)
		}
		if ns, ok := byURL[src]; ok {
			if !ns.CheckedAt.IsZero() {
				t := ns.CheckedAt
				r.Checked = &t
			}
			if !ns.PublishedAt.IsZero() {
				t := ns.PublishedAt
				r.Published = &t
				r.Quiet = now.Sub(t) > newsQuietAfter
			}
		}
		out = append(out, r)
	}
	return out
}

func sourceHost(src string) string {
	u, err := url.Parse(src)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

func (s *server) newsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.cfg.News {
		s.notFound(w, r, v)
		return
	}
	entries, err := s.st.News(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	kinds, fetched, err := s.newsKinds(r.Context())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	rows := newsRows(entries, kinds)
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	visible := 0
	for _, o := range orgs {
		if v.Scope.CanView(o.ID) {
			visible++
		}
	}
	q := r.URL.Query()
	query := strings.TrimSpace(q.Get("q"))
	if len(query) > newsQueryMax {
		query = ""
	}
	if words := strings.Fields(strings.ToLower(query)); len(words) > 0 {
		var hits []newsRow
		for _, row := range rows {
			if matchesNews(row, words) {
				hits = append(hits, row)
			}
		}
		rows = hits
	}
	body := newsBody{Total: len(rows), ShowOrgs: visible > 1, Query: query,
		Sources: newsSourceRows(s.cfg.NewsSources, fetched, entries, s.now())}
	switch {
	case q.Get("affects") == "me":
		body.Filter = "me"
	case slices.Contains(news.Categories, q.Get("category")):
		body.Filter = q.Get("category")
	}
	count := map[string]int{}
	var shown []newsRow
	for _, e := range rows {
		count[e.Category]++
		if len(e.Hosts) > 0 {
			body.Affecting++
		}
		switch body.Filter {
		case "":
		case "me":
			if len(e.Hosts) == 0 {
				continue
			}
		default:
			if e.Category != body.Filter {
				continue
			}
		}
		shown = append(shown, e)
	}
	for _, c := range news.Categories {
		if count[c] > 0 || body.Filter == c {
			body.Categories = append(body.Categories, newsChip{Slug: c, Label: categoryLabels[c], Count: count[c]})
		}
	}
	if len(shown) > newsCap {
		body.More = len(shown) - newsCap
		shown = shown[:newsCap]
	}
	body.Items = shown
	s.render(w, r, http.StatusOK, "news", v, "News", "news", body)
}

// newsAffecting counts incidents that affect at least one host the viewer
// can see (0 when news is off).
func (s *server) newsAffecting(r *http.Request, v *auth.Viewer, org string) (int, error) {
	if !s.cfg.News {
		return 0, nil
	}
	entries, err := s.st.News(r.Context(), v.Scope)
	if err != nil {
		return 0, err
	}
	kinds, _, err := s.newsKinds(r.Context())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range newsRows(entries, kinds) {
		for _, h := range e.Hosts {
			if org == "" || h.OrgSlug == org {
				n++
				break
			}
		}
	}
	return n, nil
}
