// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/leftovers"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// ChangeLink is [change_link]: links from a host's page to a
// change-management tool, which drafts the change there. The hub only
// builds the URLs; it never calls the tool. Zero is off.
type ChangeLink struct {
	URL          string // template with {org}, {host}, {package} and {finding}
	UpdatesURL   string // template with {org} and {host}: every pending update
	CollectorURL string // template with {org} and {host}: upgrade the collector
	ActionURL    string // template with {org}, {host}, {action} and {params}: any other change
	Label        string // a package link's text, e.g. "Fix"
	// AgentService is the *-agent service the host list looks for; "" = no column.
	AgentService string
	// CollectorUpgradeAction: the tool supports collector.upgrade through
	// ActionURL, so the host list links every host that's behind.
	CollectorUpgradeAction bool
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
	return hostLink(c.UpdatesURL, org, host)
}

// actionHostsMax is the most hosts one action link names (in {params}'s
// hosts); more get several links.
const actionHostsMax = 100

// hostsActionLink fills the action template for an action on several
// hosts, all in org: {host} is empty and {params} has hosts, the names
// comma-separated.
func (c ChangeLink) hostsActionLink(action, org string, hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	return c.actionLink(action, org, "", url.Values{"hosts": {strings.Join(hosts, ",")}})
}

// orgLink is a link for several hosts of one org (fleetCollectorLinks).
type orgLink struct {
	Org   string
	Hosts int
	URL   string
}

// fleetCollectorLinks drafts upgrading every collector that's behind
// among hosts (the host list as filtered): one collector.upgrade link per
// org, in chunks of actionHostsMax. None unless the tool supports the
// action (CollectorUpgradeAction).
func (c ChangeLink) fleetCollectorLinks(hosts []fleetHost) []orgLink {
	if !c.CollectorUpgradeAction {
		return nil
	}
	return c.fleetActionLinks("collector.upgrade", hosts, func(h fleetHost) bool { return h.CollectorBehind })
}

// fleetActionLinks drafts action on every host among hosts that wants it:
// one link per org, in chunks of actionHostsMax, orgs and names sorted.
func (c ChangeLink) fleetActionLinks(action string, hosts []fleetHost, wants func(fleetHost) bool) []orgLink {
	if c.ActionURL == "" {
		return nil
	}
	byOrg := map[string][]string{}
	var orgs []string
	for _, h := range hosts {
		if !wants(h) {
			continue
		}
		if byOrg[h.OrgSlug] == nil {
			orgs = append(orgs, h.OrgSlug)
		}
		byOrg[h.OrgSlug] = append(byOrg[h.OrgSlug], h.Name)
	}
	slices.Sort(orgs)
	var out []orgLink
	for _, org := range orgs {
		names := byOrg[org]
		slices.Sort(names)
		for chunk := range slices.Chunk(names, actionHostsMax) {
			out = append(out, orgLink{Org: org, Hosts: len(chunk), URL: c.hostsActionLink(action, org, chunk)})
		}
	}
	return out
}

// collectorLink fills the "Update collector" template, or is "" when the
// host's collector is current.
func (c ChangeLink) collectorLink(org, host string, behind bool) string {
	if c.CollectorURL == "" || !behind {
		return ""
	}
	return hostLink(c.CollectorURL, org, host)
}

// phpRemoveLinks maps each unused PHP version to its removal link. The
// command line's own version gets none: it has to be repointed first, which
// is a change of its own.
func (c ChangeLink) phpRemoveLinks(org, host string, runtimes []report.Runtime) map[string]string {
	if c.ActionURL == "" {
		return nil
	}
	links := map[string]string{}
	for _, rt := range runtimes {
		if rt.Use == nil || !rt.Use.Unused || rt.Use.CLI {
			continue
		}
		links[rt.Use.Minor] = c.actionLink("php.remove", org, host, url.Values{"php": {rt.Use.Minor}})
	}
	return links
}

// rebootLink drafts a reboot of the host through the action template, or
// is "" when no reboot is needed. The tool checks that the host's agent
// can reboot and asks why.
func (c ChangeLink) rebootLink(org, host string, needed bool) string {
	if !needed {
		return ""
	}
	return c.actionLink("system.reboot", org, host, nil)
}

// releaseCleanupLink drafts cleaning up what an in-place release upgrade
// left (report.Host.ReleaseLeftovers), or is "" with nothing left. Its
// {params} are Heimdall's plan for the obsolete packages, comma-separated
// names: keep (a vendor's .deb, not a leftover), replace (an obsolete one,
// with the host's release's build) and remove (nothing needs it); an
// obsolete package in none of them is for the tool to judge. The tool still asks the host's agent for the current
// state and checks the plan against it when it runs. A plan too long for
// a link is left out.
func (c ChangeLink) releaseCleanupLink(org, host string, f *leftovers.Finding) string {
	if f == nil {
		return ""
	}
	return c.actionLink("release.cleanup", org, host, cleanupParams(f))
}

// cleanupParams are a release cleanup's plan (releaseCleanupLink).
func cleanupParams(f *leftovers.Finding) url.Values {
	const maxNames = 50
	by := map[string][]string{}
	for _, l := range f.Obsolete {
		by[l.Plan] = append(by[l.Plan], l.Name)
	}
	for _, l := range f.Vendor {
		by["keep"] = append(by["keep"], l.Name)
	}
	v := url.Values{}
	for _, plan := range []string{"keep", leftovers.PlanReplace, leftovers.PlanRemove} {
		if len(by[plan]) > maxNames {
			return nil
		}
		if len(by[plan]) > 0 {
			v.Set(plan, strings.Join(by[plan], ","))
		}
	}
	return v
}

// phpUpgradeLink drafts moving one site to a newer PHP through the action
// template (php.upgrade, with {params} site=<root>&from=<x.y>), or is ""
// unless the site is served by nginx with a known PHP-FPM version and
// newer is a newer supported PHP (newerPHP). It names no target: the tool
// offers the versions the host's OS can install, and runs the change in
// stages (code first, then the new PHP-FPM beside the old, then the switch).
func (c ChangeLink) phpUpgradeLink(org, host string, site report.Site, newer string) string {
	if site.WebServer != "nginx" || !phpMinor.MatchString(site.PHPFPM) || newer == "" {
		return ""
	}
	return c.actionLink("php.upgrade", org, host, url.Values{"site": {site.Root}, "from": {site.PHPFPM}})
}

// phpMinor is a PHP minor version as the collector reports a site's
// PHP-FPM: "8.1".
var phpMinor = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}$`)

// newerPHP is the newest PHP release cycle that is newer than from,
// released and not end-of-life at now, or "" with none (or no lifecycle
// data yet).
func newerPHP(cycles []store.EOLCycle, from string, now time.Time) string {
	if vs := newerPHPs(cycles, from, now); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// newerPHPs are the PHP release cycles newer than from, released and not
// end-of-life at now, newest first.
func newerPHPs(cycles []store.EOLCycle, from string, now time.Time) []string {
	var out []string
	for _, c := range cycles {
		if !phpMinor.MatchString(c.Cycle) || compareMinor(c.Cycle, from) <= 0 || c.EOLReached ||
			(c.EOL != nil && !c.EOL.After(now)) || (c.ReleaseDate != nil && c.ReleaseDate.After(now)) || slices.Contains(out, c.Cycle) {
			continue
		}
		out = append(out, c.Cycle)
	}
	slices.SortFunc(out, func(a, b string) int { return compareMinor(b, a) })
	return out
}

// maxKernelRemove is the most kernels one removal proposal names.
const maxKernelRemove = 50

// kernelRemoveLink drafts removing old kernels (uname -r releases) through
// the action template, or is "" with none. The tool's agent removes only
// those still installed and older than the running kernel. A server that
// skipped many kernel updates keeps a dozen or more, so the link names up
// to maxKernelRemove.
func (c ChangeLink) kernelRemoveLink(org, host string, kernels []string) string {
	if len(kernels) == 0 || len(kernels) > maxKernelRemove {
		return ""
	}
	return c.actionLink("kernel.remove", org, host, url.Values{"kernels": {strings.Join(kernels, ",")}})
}

// phpRemoveAllLink is one removal link for every unused PHP version that
// has its own (see phpRemoveLinks), and how many that is: "" unless there
// are at least two. The tool makes one proposal per version, each with its
// own checks, backup and rollback.
func (c ChangeLink) phpRemoveAllLink(org, host string, links map[string]string) (string, int) {
	if len(links) < 2 {
		return "", 0
	}
	versions := slices.Collect(maps.Keys(links))
	slices.SortFunc(versions, compareMinor)
	return c.actionLink("php.remove", org, host, url.Values{"php": {strings.Join(versions, ",")}}), len(versions)
}

// compareMinor orders PHP versions numerically: 7.4 before 8.1 before 8.10.
func compareMinor(a, b string) int {
	am, an, _ := strings.Cut(a, ".")
	bm, bn, _ := strings.Cut(b, ".")
	x, _ := strconv.Atoi(am)
	y, _ := strconv.Atoi(bm)
	if x != y {
		return cmp.Compare(x, y)
	}
	x, _ = strconv.Atoi(an)
	y, _ = strconv.Atoi(bn)
	return cmp.Compare(x, y)
}

// actionLink fills the generic action template. A new action needs a button
// and a handler in the tool, not another setting.
func (c ChangeLink) actionLink(action, org, host string, params url.Values) string {
	if c.ActionURL == "" {
		return ""
	}
	return strings.NewReplacer("{action}", url.QueryEscape(action), "{params}", params.Encode()).Replace(hostLink(c.ActionURL, org, host))
}

// hostLink fills a template that takes {org} and {host}.
func hostLink(tmpl, org, host string) string {
	return strings.NewReplacer("{org}", url.QueryEscape(org), "{host}", url.QueryEscape(host)).Replace(tmpl)
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

// nginxHTTP2OffLink drafts turning HTTP/2 off in nginx (action
// nginx.http2_off, no params), or is "" unless nginx speaks HTTP/2 and an
// open nginx.org advisory about HTTP/2 applies. The tool's agent turns it
// off in every server block and http{}, checks the configuration and
// reloads, keeping a backup to turn it back on once nginx is updated.
func (c ChangeLink) nginxHTTP2OffLink(org, host string, h report.Host) string {
	if h.Nginx == nil || h.Nginx.HTTP2 == 0 || len(h.NginxHTTP2Findings()) == 0 {
		return ""
	}
	return c.actionLink("nginx.http2_off", org, host, nil)
}

// nginxRestartLink drafts restarting nginx (action service.restart with
// unit=nginx.service), or is "" unless the running nginx predates its
// binary: a reload keeps the old code running.
func (c ChangeLink) nginxRestartLink(org, host string, h report.Host) string {
	if h.Nginx == nil || h.Nginx.Restart != "yes" {
		return ""
	}
	return c.actionLink("service.restart", org, host, url.Values{"unit": {"nginx.service"}})
}

// nginxSourceSwitchLink drafts moving nginx from Ondřej Surý's removed
// ondrej/nginx PPA to nginx.org's packages (action nginx.source.nginx_org,
// no params), or is "" unless nginx is Surý's build. The tool's agent
// removes the PPA's sources file, adds nginx.org's key, repository and pin,
// drops load_module lines for modules nginx.org doesn't ship, upgrades,
// checks the configuration and restarts.
func (c ChangeLink) nginxSourceSwitchLink(org, host string, h report.Host) string {
	if h.NginxSuryBuild == "" {
		return ""
	}
	return c.actionLink("nginx.source.nginx_org", org, host, nil)
}

// phpSourceMoveLink drafts moving PHP from Ondřej Surý's deprecated,
// frozen ondrej/php PPA to packages.sury.org, its replacement (action
// php.source.sury_org, no params), or is "" unless apt still gets packages
// from the PPA. The tool's agent installs debsuryorg-repository-php from
// the PPA, which adds packages.sury.org's source and key, then removes the
// PPA's source; it installs, upgrades or restarts no PHP package.
func (c ChangeLink) phpSourceMoveLink(org, host string, h report.Host) string {
	if len(h.PHPFromPPA) == 0 {
		return ""
	}
	return c.actionLink("php.source.sury_org", org, host, nil)
}

// fleetPHPMoveLinks drafts moving PHP to packages.sury.org on every host
// among hosts (the host list as filtered) that still gets it from the
// ondrej/php PPA: one link per org, in chunks of actionHostsMax.
func (c ChangeLink) fleetPHPMoveLinks(hosts []fleetHost) []orgLink {
	return c.fleetActionLinks("php.source.sury_org", hosts, func(h fleetHost) bool { return len(h.R.PHPFromPPA) > 0 })
}

// nginxUpdateLink drafts upgrading nginx through the package template, for
// the nginx findings an update can fix now (see fixableIDs), or is "" with
// none (no fix released, as for a distro build the distro hasn't patched).
func (c ChangeLink) nginxUpdateLink(org, host string, h report.Host) string {
	var fs []report.Finding
	for _, f := range h.Findings {
		if f.Package == "nginx" && f.Site == "" {
			fs = append(fs, f)
		}
	}
	return c.link(org, host, "nginx", fixableIDs(fs))
}
