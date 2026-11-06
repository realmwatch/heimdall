// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// ChangeLink is a link from findings to a change-management tool, which
// drafts the fix there ("Fix" on host pages). Heimdall only builds the
// link: it sends the tool nothing and holds no credential for it.
type ChangeLink struct {
	// URL is an https template with {org}, {host}, {package} and
	// {finding} placeholders (finding ids, comma-separated); "" is off.
	URL string `toml:"url"`
	// UpdatesURL is an https template with {org} and {host} placeholders,
	// for "Install all updates": the tool drafts every pending update on
	// the host, so no finding ids are involved. "" is off.
	UpdatesURL string `toml:"updates_url"`
	Label      string `toml:"label"` // a package link's text; "" is "Fix"
}

// DefaultChangeLabel is ChangeLink.Label when it isn't set.
const DefaultChangeLabel = "Fix"

// ChangePlaceholders are the placeholders a ChangeLink URL may use.
var ChangePlaceholders = []string{"{org}", "{host}", "{package}", "{finding}"}

// UpdatesPlaceholders are the placeholders a ChangeLink UpdatesURL may use.
var UpdatesPlaceholders = []string{"{org}", "{host}"}

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
	validateLinkTemplate("change_link.url", c.URL, ChangePlaceholders, add)
	validateLinkTemplate("change_link.updates_url", c.UpdatesURL, UpdatesPlaceholders, add)
}

func validateLinkTemplate(key, tmpl string, placeholders []string, add func(string, ...any)) {
	if tmpl == "" {
		return
	}
	for _, p := range bracesRe.FindAllString(tmpl, -1) {
		if !slices.Contains(placeholders, p) {
			add("%s: unknown placeholder %s (use %s)", key, p, strings.Join(placeholders, ", "))
			return
		}
	}
	filled := bracesRe.ReplaceAllString(tmpl, "x")
	if u, err := url.Parse(filled); err != nil || !httpsOrLoopback(u) || u.User != nil || u.Fragment != "" {
		add("%s: must be an https URL (plain http only for loopback), with no credentials or #fragment", key)
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
