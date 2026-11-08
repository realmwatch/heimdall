// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// ChangeLink is [change_link]: links from a host's page to a
// change-management tool, which drafts the change there. The hub only
// builds the URLs; it never calls the tool. Zero is off.
type ChangeLink struct {
	URL        string // template with {org}, {host}, {package} and {finding}
	UpdatesURL string // template with {org} and {host}: every pending update
	Label      string // a package link's text, e.g. "Fix"
	// AgentService is the *-agent service the host list looks for; "" = no column.
	AgentService string
}

// link fills the template, escaping each value. ids are the findings to
// fix, most important first, capped at store.MaxFindingIDs.
func (c ChangeLink) link(org, host, pkg string, ids []int64) string {
	if c.URL == "" || len(ids) == 0 {
		return ""
	}
	ids = ids[:min(len(ids), store.MaxFindingIDs)]
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.NewReplacer(
		"{org}", url.QueryEscape(org),
		"{host}", url.QueryEscape(host),
		"{package}", url.QueryEscape(pkg),
		"{finding}", strings.Join(parts, ","),
	).Replace(c.URL)
}

// fixableIDs are the ids of the findings an update can fix now: a fix is
// released and the exposure is live (as the Fixable filter counts them).
func fixableIDs(list []report.Finding) []int64 {
	var ids []int64
	for _, f := range list {
		if f.Fixed != "" && live(f) && !f.Dev && f.ID > 0 {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

// updatesLink fills the "Install all updates" template, or is "" with
// nothing pending.
func (c ChangeLink) updatesLink(org, host string, pending int) string {
	if c.UpdatesURL == "" || pending == 0 {
		return ""
	}
	return strings.NewReplacer("{org}", url.QueryEscape(org), "{host}", url.QueryEscape(host)).Replace(c.UpdatesURL)
}

// addChangeLinks puts the change-management links on an OS findings view:
// one for every fixable finding shown, one per package, and one for all of
// the host's pending updates.
func (c ChangeLink) addChangeLinks(fv *findingsView, org, host string, pending int) {
	fv.UpdatesURL, fv.UpdatesCount = c.updatesLink(org, host, pending), pending
	if c.URL == "" {
		return
	}
	fv.ChangeLabel = c.Label
	ids := fixableIDs(fv.shown)
	fv.ChangeURL, fv.ChangeCount = c.link(org, host, "", ids), len(ids)
	for i := range fv.Groups {
		g := &fv.Groups[i]
		g.ChangeURL = c.link(org, host, g.Package, fixableIDs(g.Findings))
		g.ChangeLabel = c.Label
	}
}
