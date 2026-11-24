// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// A patch plan's bulk actions: a column per change the tool can propose
// for several hosts, showing which of the plan's hosts need it, and in
// bulk-actions mode a button above it that names those hosts (the ticked
// ones, or every one when none is ticked). A column's button goes away
// once no host needs it, so an empty header means that job is done across
// the plan.

// planRow is a plan item and what its host needs.
type planRow struct {
	store.PlanItem
	Reported bool
	F        fleetHost
}

// needs reports whether the row's host needs action, from its last report.
func (r planRow) needs(action string) bool {
	if !r.Reported {
		return false
	}
	h := r.F
	switch action {
	case "updates.install":
		return h.Pending > 0
	case "system.reboot":
		return h.Reboot || h.R.Counts.RebootPending > 0
	case "kernel.remove":
		return len(h.R.OldKernelReleases) > 0
	case "collector.upgrade":
		return h.CollectorBehind
	case "php.source.sury_org":
		return len(h.R.PHPFromPPA) > 0
	case "nginx.source.nginx_org":
		return h.R.NginxSuryBuild != ""
	case "service.restart":
		return h.NginxRestart
	}
	return false
}

// Needs is the actions the row's host needs, space-separated (the row
// box's data-needs).
func (r planRow) Needs() string {
	var out []string
	for _, a := range config.BulkActionNames {
		if r.needs(a) {
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

// Cell is what the row shows in action's column, and its tooltip.
func (r planRow) Cell(action string) planCell {
	if !r.Reported {
		return planCell{}
	}
	h := r.F
	need := r.needs(action)
	switch action {
	case "updates.install":
		if !need {
			return planCell{Text: "0"}
		}
		return planCell{Text: strconv.Itoa(h.PendingSecurity) + " / " + strconv.Itoa(h.Pending), Title: strconv.Itoa(h.PendingSecurity) + " security of " + strconv.Itoa(h.Pending) + " pending", Need: true, Bad: h.PendingSecurity > 0}
	case "system.reboot":
		if !need {
			return planCell{}
		}
		t := "Installed updates need a reboot"
		if h.R.NewerKernel != "" {
			t = "Kernel " + h.R.NewerKernel + " is installed but not running"
		}
		return planCell{Text: "needed", Title: t, Need: true}
	case "kernel.remove":
		if !need {
			return planCell{}
		}
		return planCell{Text: strconv.Itoa(len(h.R.OldKernelReleases)), Title: strings.Join(h.R.OldKernelReleases, ", "), Need: true}
	case "collector.upgrade":
		if !need {
			return planCell{}
		}
		return planCell{Text: h.Collector, Title: "Collector " + h.Collector + " is behind", Need: true}
	case "php.source.sury_org":
		if !need {
			return planCell{}
		}
		return planCell{Text: "on the PPA", Title: strconv.Itoa(len(h.R.PHPFromPPA)) + " packages from the deprecated ondrej/php PPA", Need: true, Bad: true}
	case "nginx.source.nginx_org":
		if !need {
			return planCell{}
		}
		return planCell{Text: "on the PPA", Title: "nginx " + h.R.NginxSuryBuild + " from the removed ondrej/nginx PPA", Need: true, Bad: true}
	case "service.restart":
		if !need {
			return planCell{}
		}
		return planCell{Text: "needed", Title: "nginx runs the code from before its update", Need: true}
	}
	return planCell{}
}

type planCell struct {
	Text, Title string
	Need, Bad   bool
}

// planColumn is one action's column.
type planColumn struct {
	Action string
	Label  string // the header
	Verb   string // the button's text
	Count  int    // hosts that need it
	// Bulk: the tool takes it for several hosts ([change_link]
	// bulk_actions); Links name every host that needs it, per org, and
	// URL is the template the page fills for the ticked ones.
	Bulk  bool
	Links []planUpdates
	URL   string
}

// planActions are the columns, in order; Always ones show even when no
// host needs them.
var planActions = []struct {
	Action, Label, Verb string
	Always              bool
}{
	{"updates.install", "Updates (security / all)", "Install updates", true},
	{"system.reboot", "Reboot", "Reboot", true},
	{"kernel.remove", "Old kernels", "Remove old kernels", true},
	{"collector.upgrade", "Collector", "Upgrade collector", true},
	{"php.source.sury_org", "PHP source", "Move PHP to packages.sury.org", false},
	{"nginx.source.nginx_org", "nginx source", "Move nginx to nginx.org", false},
	{"service.restart", "nginx restart", "Restart nginx", false},
}

// The placeholders a column's URL leaves for the page to fill.
const (
	orgToken   = "__org__"
	hostsToken = "__hosts__"
)

// planColumns are the columns the plan shows, with each one's links.
// Links are built only when canBulk.
func planColumns(c ChangeLink, rows []planRow, canBulk bool) []planColumn {
	var out []planColumn
	for _, a := range planActions {
		col := planColumn{Action: a.Action, Label: a.Label, Verb: a.Verb}
		var need []planRow
		for _, r := range rows {
			if r.needs(a.Action) {
				need = append(need, r)
			}
		}
		col.Count = len(need)
		if col.Count == 0 && !a.Always {
			continue
		}
		if canBulk && c.Bulk(a.Action) {
			col.Bulk = true
			col.Links = orgChunks(c, a.Action, need)
			col.URL = c.actionLink(a.Action, orgToken, "", url.Values{"hosts": {hostsToken}})
			if a.Action == "service.restart" {
				col.URL = c.actionLink(a.Action, orgToken, "", url.Values{"hosts": {hostsToken}, "unit": {"nginx.service"}})
			}
		}
		out = append(out, col)
	}
	return out
}

// orgChunks links action for rows: one link per org, in chunks of
// actionHostsMax, orgs and names sorted.
func orgChunks(c ChangeLink, action string, rows []planRow) []planUpdates {
	byOrg := map[string][]string{}
	var orgs []string
	for _, r := range rows {
		org := r.Host.OrgSlug
		if byOrg[org] == nil {
			orgs = append(orgs, org)
		}
		byOrg[org] = append(byOrg[org], r.Host.Name)
	}
	slices.Sort(orgs)
	var out []planUpdates
	for _, org := range orgs {
		names := byOrg[org]
		slices.Sort(names)
		for chunk := range slices.Chunk(names, actionHostsMax) {
			params := url.Values{"hosts": {strings.Join(chunk, ",")}}
			if action == "service.restart" {
				params.Set("unit", "nginx.service")
			}
			out = append(out, planUpdates{Org: org, Hosts: len(chunk), URL: c.actionLink(action, org, "", params)})
		}
	}
	return out
}

// planRows pairs each item with its host's fleet row.
func planRows(items []store.PlanItem, fleet []fleetHost) []planRow {
	by := make(map[int64]fleetHost, len(fleet))
	for _, h := range fleet {
		by[h.ID] = h
	}
	rows := make([]planRow, len(items))
	for i, it := range items {
		h, ok := by[it.Host.ID]
		rows[i] = planRow{PlanItem: it, F: h, Reported: ok && h.Reported}
	}
	return rows
}

// planBatches are the plan's batch numbers, ascending.
func planBatches(items []store.PlanItem) []int {
	var out []int
	for _, it := range items {
		if !slices.Contains(out, it.Batch) {
			out = append(out, it.Batch)
		}
	}
	slices.SortFunc(out, cmp.Compare)
	return out
}
