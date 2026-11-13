// SPDX-License-Identifier: AGPL-3.0-or-later

package news

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Articles are RSS 2.0 or Atom feeds of security news. Unlike a curated
// incident list they carry no CVE, severity or status fields, so Heimdall
// reads the CVE IDs out of each article's text and keeps only articles
// that name at least one: those are the ones a host's findings can match.
// An article is "live" for ArticleLiveFor after it was published.

// ArticleLiveFor is how long an article counts as current news.
const ArticleLiveFor = 30 * 24 * time.Hour

// roundupCVEs is the most CVE IDs an article's full text may name before
// it's treated as a roundup (a weekly list of hundreds of advisories):
// then only its title and summary are read for CVE IDs, so one roundup
// doesn't put every finding in the news.
const roundupCVEs = 20

// maxArticleSummary caps the plain-text summary kept from an article.
const maxArticleSummary = 600

var (
	articleCVE = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	htmlScript = regexp.MustCompile(`(?is)<script\b.*?</script\s*>|<style\b.*?</style\s*>`)
	htmlTag    = regexp.MustCompile(`(?s)<[^>]*>`)
)

type xmlDoc struct {
	XMLName xml.Name
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
	Entries []atomEntry `xml:"entry"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"http://purl.org/dc/elements/1.1/ date"`
	Description string `xml:"description"`
	Content     string `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
}

type atomEntry struct {
	Title string `xml:"title"`
	Links []struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
	} `xml:"link"`
	ID        string `xml:"id"`
	Published string `xml:"published"`
	Updated   string `xml:"updated"`
	Summary   string `xml:"summary"`
	Content   string `xml:"content"`
}

// article is one feed entry before validation.
type article struct {
	id, title, link, summary, content string
	published, updated                string
}

// ParseArticles parses an RSS 2.0 or Atom feed. It fails if the document
// isn't one or has no entries at all; a feed whose entries name no CVE is
// valid and yields no items (Unrelated counts them).
func ParseArticles(raw []byte, now time.Time) (*Feed, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = false
	d.Entity = xml.HTMLEntity
	d.CharsetReader = func(charset string, in io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "utf-8", "utf8", "us-ascii", "ascii":
			return in, nil
		}
		return nil, fmt.Errorf("charset %q isn't supported", charset)
	}
	var doc xmlDoc
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("news: not an RSS or Atom feed: %w", err)
	}
	var entries []article
	switch doc.XMLName.Local {
	case "rss":
		for _, it := range doc.Channel.Items {
			date := it.PubDate
			if date == "" {
				date = it.Date
			}
			entries = append(entries, article{id: it.GUID, title: it.Title, link: it.Link,
				summary: it.Description, content: it.Content, published: date, updated: date})
		}
	case "feed":
		for _, e := range doc.Entries {
			a := article{id: e.ID, title: e.Title, summary: e.Summary, content: e.Content,
				published: e.Published, updated: e.Updated}
			for _, l := range e.Links {
				if l.Rel == "" || l.Rel == "alternate" {
					a.link = l.Href
					break
				}
			}
			if a.published == "" {
				a.published = a.updated
			}
			entries = append(entries, a)
		}
	default:
		return nil, fmt.Errorf("news: <%s> isn't an RSS or Atom feed", doc.XMLName.Local)
	}
	if len(entries) == 0 {
		return nil, errors.New("news: feed has no entries; keeping the stored copy")
	}
	if len(entries) > maxItems {
		return nil, fmt.Errorf("news: %d entries is more than the %d allowed", len(entries), maxItems)
	}
	f := &Feed{Articles: true}
	seen := map[string]bool{}
	for _, a := range entries {
		it, ok := a.item(now)
		if !it.UpdatedAt.IsZero() && it.UpdatedAt.After(f.Newest) {
			f.Newest = it.UpdatedAt
		}
		switch {
		case !ok || seen[it.Slug]:
			f.Dropped++
		case len(it.CVEs) == 0:
			f.Unrelated++
		default:
			seen[it.Slug] = true
			f.Items = append(f.Items, it)
		}
	}
	if f.Dropped == len(entries) {
		return f, fmt.Errorf("news: %w (%d dropped)", errEmptyFeed, f.Dropped)
	}
	return f, nil
}

// item validates one entry. A dated entry that's otherwise unusable still
// returns its dates, so the feed's newest date counts it.
func (a article) item(now time.Time) (Item, bool) {
	var it Item
	var ok bool
	if it.StartedAt, ok = parseArticleTime(a.published); !ok {
		return it, false
	}
	it.UpdatedAt = it.StartedAt
	if u, ok := parseArticleTime(a.updated); ok && u.After(it.StartedAt) {
		it.UpdatedAt = u
	}
	link := strings.TrimSpace(a.link)
	if link == "" && strings.HasPrefix(strings.TrimSpace(a.id), "https://") {
		link = strings.TrimSpace(a.id)
	}
	if it.URL, ok = httpsURL(link); !ok {
		return it, false
	}
	it.Title = clip(plain(a.title), maxTitle)
	if it.Title == "" {
		return it, false
	}
	it.Summary = clip(plain(a.summary), maxArticleSummary)
	if it.Summary == "" {
		it.Summary = clip(plain(a.content), maxArticleSummary)
	}
	id := strings.TrimSpace(a.id)
	if id == "" {
		id = it.URL
	}
	sum := sha256.Sum256([]byte(id))
	it.Slug = "a-" + hex.EncodeToString(sum[:10])

	head := it.Title + "\n" + plain(a.summary)
	it.CVEs = cveIDs(head + "\n" + plain(a.content))
	if len(it.CVEs) > roundupCVEs {
		it.CVEs = cveIDs(head)
	}
	if len(it.CVEs) > maxCVEs {
		it.CVEs = it.CVEs[:maxCVEs]
	}

	it.Category = "patch"
	if l := strings.ToLower(head); strings.Contains(l, "supply chain") || strings.Contains(l, "supply-chain") ||
		strings.Contains(l, "malicious package") {
		it.Category = "supply-chain"
	}
	it.Severity = "unknown"
	it.Status = "live"
	if end := it.StartedAt.Add(ArticleLiveFor); !end.After(now) {
		it.Status, it.ClosedAt = "closed", &end
	}
	it.Stacks, it.Tags, it.Affected, it.Fixed = []string{}, []string{}, []string{}, []string{}
	return it, true
}

// cveIDs are the distinct CVE IDs named in s, upper-cased, in order.
func cveIDs(s string) []string {
	var out []string
	for _, m := range articleCVE.FindAllString(s, -1) {
		if m = strings.ToUpper(m); !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// plain turns an article's HTML into one line of text: no scripts, styles
// or tags, entities decoded, control characters and runs of whitespace
// collapsed to a space. The result is still untrusted and only ever
// rendered escaped.
func plain(s string) string {
	s = htmlScript.ReplaceAllString(s, " ")
	s = htmlTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ") // Fields also splits on no-break spaces
}

// clip shortens s to at most max characters, ending in "…" when cut.
func clip(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)[:max-1]
	return strings.TrimRight(string(r), " ") + "…"
}

var articleTimeLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339Nano,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04 -0700", time.DateOnly,
}

// parseArticleTime accepts the dates RSS and Atom feeds use in practice.
func parseArticleTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range articleTimeLayouts {
		if t, err := time.Parse(l, s); err == nil && t.Year() >= 1990 && t.Year() <= 2200 {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
