// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ChangeLink is a link from findings to a change-management tool, which
// drafts the fix there ("Fix" on host pages). Heimdall only builds the
// link: it sends the tool nothing and holds no credential for it.
type ChangeLink struct {
	// URL is an https template with {org}, {host}, {package} and
	// {finding} placeholders (finding ids, comma-separated); "" is off.
	URL   string `toml:"url"`
	Label string `toml:"label"` // the link's text; "" is "Fix"
}

// DefaultChangeLabel is ChangeLink.Label when it isn't set.
const DefaultChangeLabel = "Fix"

// ChangePlaceholders are the placeholders a ChangeLink URL may use.
var ChangePlaceholders = []string{"{org}", "{host}", "{package}", "{finding}"}

// LinkLabel is Label, or DefaultChangeLabel.
func (c ChangeLink) LinkLabel() string {
	if c.Label == "" {
		return DefaultChangeLabel
	}
	return c.Label
}

var bracesRe = regexp.MustCompile(`\{[^}]*\}`)

func (c ChangeLink) validate(add func(string, ...any)) {
	if n := utf8.RuneCountInString(c.Label); n > 24 || strings.ContainsFunc(c.Label, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		add("change_link.label: at most 24 printable characters")
	}
	if c.URL == "" {
		return
	}
	for _, p := range bracesRe.FindAllString(c.URL, -1) {
		known := false
		for _, k := range ChangePlaceholders {
			known = known || p == k
		}
		if !known {
			add("change_link.url: unknown placeholder %s (use %s)", p, strings.Join(ChangePlaceholders, ", "))
			return
		}
	}
	filled := bracesRe.ReplaceAllString(c.URL, "x")
	if u, err := url.Parse(filled); err != nil || !httpsOrLoopback(u) || u.User != nil || u.Fragment != "" {
		add("change_link.url: must be an https URL (plain http only for loopback), with no credentials or #fragment")
	}
}

// ReportWebhook posts a signed report.received event to URL each time a
// host's report is accepted, so another tool knows when to read the
// host's findings again. The event carries no inventory or findings. The
// signing secret is a systemd credential, stored with
// `heimdall report-webhook set`, never in this file.
type ReportWebhook struct {
	URL string `toml:"url"` // "" is off
}

func (w ReportWebhook) validate(add func(string, ...any)) {
	if w.URL == "" {
		return
	}
	if u, err := url.Parse(w.URL); err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		add("report_webhook.url: must be an https URL with no credentials or #fragment")
	}
}

func httpsOrLoopback(u *url.URL) bool {
	switch {
	case u.Hostname() == "":
		return false
	case u.Scheme == "https":
		return true
	}
	h := u.Hostname()
	return u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")
}
