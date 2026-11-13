// SPDX-License-Identifier: AGPL-3.0-or-later

package news

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

var articlesNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func rssFeed(items ...string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Example news</title>
<link>https://news.example.com/</link>` + strings.Join(items, "\n") + `</channel></rss>`)
}

func rssEntry(guid, title, link, date, desc, content string) string {
	return fmt.Sprintf(`<item><title>%s</title><link>%s</link><guid isPermaLink="false">%s</guid><pubDate>%s</pubDate>
<description><![CDATA[%s]]></description><content:encoded><![CDATA[%s]]></content:encoded></item>`, title, link, guid, date, desc, content)
}

func TestParseArticlesRSS(t *testing.T) {
	var roundup strings.Builder
	for i := range roundupCVEs + 5 {
		fmt.Fprintf(&roundup, "<li>CVE-2026-%05d</li>", 10000+i)
	}
	raw := rssFeed(
		rssEntry("1", "Critical ExampleSSL flaw (cve-2026-11111) exploited", "https://news.example.com/a/1",
			"Thu, 12 Nov 2026 16:38:02 +0000",
			`<p>Attackers are <b>exploiting</b> it&nbsp;now &amp; a patch is out.</p><script>alert(1)</script>`, ""),
		rssEntry("2", "A breach with no CVE", "https://news.example.com/a/2", "Fri, 13 Nov 2026 09:00:00 +0000",
			"Customer data leaked.", ""),
		rssEntry("3", "Weekly vulnerability report", "https://news.example.com/a/3", "Wed, 11 Nov 2026 10:00:00 GMT",
			"Hundreds of plugins.", roundup.String()),
		rssEntry("4", "Widget plugin file upload flaw", "https://news.example.com/a/4", "Tue, 10 Nov 2026 10:00:00 +0000",
			"An upload flaw.", "<p>Tracked as CVE-2026-22222 and CVE-2026-22222.</p>"),
		rssEntry("5", "Old news about CVE-2026-33333", "https://news.example.com/a/5", "Mon, 05 Oct 2026 10:00:00 +0000", "", ""),
		rssEntry("6", "Plain http link CVE-2026-44444", "http://news.example.com/a/6", "Tue, 10 Nov 2026 10:00:00 +0000", "", ""),
		rssEntry("1", "Duplicate of CVE-2026-11111", "https://news.example.com/a/1", "Tue, 10 Nov 2026 10:00:00 +0000", "", ""),
		rssEntry("7", "Malicious package in a supply chain attack: CVE-2026-55555", "https://news.example.com/a/7",
			"Tue, 10 Nov 2026 10:00:00 +0000", "", ""),
	)
	f, err := ParseAny(raw, articlesNow)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Articles || f.Unrelated != 2 || f.Dropped != 2 {
		t.Errorf("articles %v, unrelated %d (no CVE, roundup), dropped %d (http, duplicate)", f.Articles, f.Unrelated, f.Dropped)
	}
	if !f.Newest.Equal(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("newest %v: the newest entry counts even without a CVE", f.Newest)
	}
	var titles []string
	for _, it := range f.Items {
		titles = append(titles, it.Title)
	}
	if len(f.Items) != 4 {
		t.Fatalf("items %q", titles)
	}
	a := f.Items[0]
	if !slices.Equal(a.CVEs, []string{"CVE-2026-11111"}) || a.Status != "live" || a.ClosedAt != nil ||
		a.Category != "patch" || a.Severity != "unknown" || a.URL != "https://news.example.com/a/1" ||
		!strings.HasPrefix(a.Slug, "a-") || !slugRe.MatchString(a.Slug) {
		t.Errorf("item %+v", a)
	}
	if a.Summary != "Attackers are exploiting it now & a patch is out." {
		t.Errorf("summary %q: tags and scripts go, entities decode", a.Summary)
	}
	if !a.StartedAt.Equal(time.Date(2026, 11, 12, 16, 38, 2, 0, time.UTC)) {
		t.Errorf("started %v", a.StartedAt)
	}
	if w := f.Items[1]; !slices.Equal(w.CVEs, []string{"CVE-2026-22222"}) {
		t.Errorf("a CVE named only in the article body: %v", w.CVEs)
	}
	if old := f.Items[2]; old.Status != "closed" || old.ClosedAt == nil ||
		!old.ClosedAt.Equal(old.StartedAt.Add(ArticleLiveFor)) {
		t.Errorf("an article older than %v is closed: %+v", ArticleLiveFor, old)
	}
	if chain := f.Items[3]; chain.Category != "supply-chain" {
		t.Errorf("category %q", chain.Category)
	}
}

func TestParseArticlesAtom(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Example</title>
<entry><title type="html">Fix for CVE-2026-66666 &lt;b&gt;now&lt;/b&gt;</title>
<link rel="self" href="https://news.example.com/self/1"/><link rel="alternate" href="https://news.example.com/b/1"/>
<id>tag:news.example.com,2026:1</id><published>2026-11-09T08:00:00Z</published><updated>2026-11-10T08:00:00Z</updated>
<summary>Short summary.</summary></entry>
</feed>`)
	f, err := ParseAny(raw, articlesNow)
	if err != nil || len(f.Items) != 1 {
		t.Fatalf("%v %+v", err, f)
	}
	it := f.Items[0]
	if it.URL != "https://news.example.com/b/1" || it.Title != "Fix for CVE-2026-66666 now" ||
		!it.UpdatedAt.Equal(time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)) || !it.StartedAt.Before(it.UpdatedAt) {
		t.Errorf("entry %+v", it)
	}
}

func TestParseArticlesRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"html page":     `<!doctype html><html><body>maintenance</body></html>`,
		"no entries":    `<rss version="2.0"><channel><title>x</title></channel></rss>`,
		"all malformed": `<rss version="2.0"><channel><item><title>CVE-2026-1111</title></item></channel></rss>`,
		"other charset": `<?xml version="1.0" encoding="windows-1252"?><rss><channel><item/></channel></rss>`,
		"neither":       `maintenance`,
	} {
		if _, err := ParseAny([]byte(raw), articlesNow); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// A quiet week: entries, but none names a CVE. Not an error.
	f, err := ParseAny(rssFeed(rssEntry("1", "A breach", "https://news.example.com/a/1", "Thu, 12 Nov 2026 16:38:02 +0000", "", "")), articlesNow)
	if err != nil || len(f.Items) != 0 || f.Unrelated != 1 {
		t.Errorf("%v %+v", err, f)
	}
}

func TestPlainAndClip(t *testing.T) {
	if got := plain("a\x00b<br/>c\n\n d &lt;x&gt;"); got != "a b c d <x>" {
		t.Errorf("plain %q", got)
	}
	if got := clip("abcdef", 4); got != "abc…" || clip("abc", 4) != "abc" {
		t.Errorf("clip %q", got)
	}
}
