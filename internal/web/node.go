// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// Node.js versions per site: the change-management tool keeps extra
// majors side by side under /opt/node/<major> (nodejs.org's tarballs),
// next to the host's default from apt. The tool accepts exactly these
// shapes, so a link is offered only when its params match them.
var (
	nodeMajorRe = regexp.MustCompile(`^[0-9]{2}$`)
	optNodeRe   = regexp.MustCompile(`^(/opt/node/([0-9]{2}))/bin/node$`)
	nvmNodeRe   = regexp.MustCompile(`^/home/[^/]+/\.nvm/versions/node/v[0-9]+\.[0-9]+\.[0-9]+/bin/node$`)
)

// nodeLinks are the proposals for one Node.js binary on the host page.
type nodeLinks struct {
	Update  string     // nodejs.update: an /opt install behind its major's latest
	Remove  string     // nodejs.remove: an /opt install nothing runs or uses
	Migrate []siteLink // nodejs.migrate: a site running nvm's Node, per site
	// DefaultUpgrade (nodejs.default_upgrade) moves the apt default to a
	// newer major; Newest is the newest LTS, and Breaks the sites on the
	// default whose requirement it wouldn't meet.
	DefaultUpgrade string
	Newest         string
	Breaks         []string
}

type siteLink struct{ Site, URL string }

// newestNodeLTS is the newest supported, released, even (LTS) Node.js
// major newer than from, or "".
func newestNodeLTS(cycles []store.EOLCycle, from string, now time.Time) string {
	f, err := strconv.Atoi(from)
	if err != nil {
		return ""
	}
	best := 0
	for _, c := range cycles {
		m, err := strconv.Atoi(c.Cycle)
		if err != nil || m%2 != 0 || m <= f || m <= best || c.EOLReached ||
			(c.EOL != nil && !c.EOL.After(now)) || (c.ReleaseDate != nil && c.ReleaseDate.After(now)) {
			continue
		}
		best = m
	}
	if best == 0 {
		return ""
	}
	return strconv.Itoa(best)
}

// nodeSupported reports whether major is a released Node.js major that
// isn't end-of-life at now.
func nodeSupported(cycles []store.EOLCycle, major string, now time.Time) bool {
	for _, c := range cycles {
		if c.Cycle == major {
			return !c.EOLReached && (c.EOL == nil || c.EOL.After(now)) && (c.ReleaseDate == nil || !c.ReleaseDate.After(now))
		}
	}
	return false
}

// nodeHostLinks are the host page's Node.js proposals, by binary path;
// nil without the action template.
func (c ChangeLink) nodeHostLinks(org, host string, rep report.Host, cycles []store.EOLCycle, now time.Time) map[string]nodeLinks {
	if c.ActionURL == "" {
		return nil
	}
	out := map[string]nodeLinks{}
	for _, rt := range rep.Runtimes {
		if rt.Name != "nodejs" || rt.Path == "" {
			continue
		}
		var l nodeLinks
		switch rt.Kind {
		case "opt":
			m := optNodeRe.FindStringSubmatch(rt.Path)
			if m == nil {
				continue
			}
			if rt.Latest != "" {
				l.Update = c.actionLink("nodejs.update", org, host, url.Values{"node": {m[1]}})
			}
			if !rt.Running && len(rt.Sites) == 0 {
				l.Remove = c.actionLink("nodejs.remove", org, host, url.Values{"node": {m[1]}})
			}
		case "nvm":
			if !nvmNodeRe.MatchString(rt.Path) {
				continue
			}
			for _, s := range rt.Sites {
				if validSiteRoot(s) {
					l.Migrate = append(l.Migrate, siteLink{s, c.actionLink("nodejs.migrate", org, host, url.Values{"node": {rt.Path}, "site": {s}})})
				}
			}
		case "apt":
			from := report.NodeMajor(rt.Version)
			newest := newestNodeLTS(cycles, from, now)
			if !nodeMajorRe.MatchString(from) || newest == "" {
				continue
			}
			l.Newest = newest
			l.DefaultUpgrade = c.actionLink("nodejs.default_upgrade", org, host, url.Values{"from": {from}})
			n, _ := strconv.Atoi(newest)
			for _, s := range rep.Sites {
				if s.NodeBin != "" && s.NodeBin != report.AptNodePath {
					continue // on its own Node
				}
				if r, ok := report.ParseNodeRange(s.NodeRequirement); ok && !r.Allows(n) {
					l.Breaks = append(l.Breaks, s.Root)
				}
			}
			slices.Sort(l.Breaks)
		}
		if l.Update != "" || l.Remove != "" || len(l.Migrate) > 0 || l.DefaultUpgrade != "" {
			out[rt.Path] = l
		}
	}
	return out
}

// validSiteRoot is a site root the tool accepts: absolute, not "/".
func validSiteRoot(root string) bool { return len(root) > 1 && root[0] == '/' }

// nodeSiteLinks are a site page's Node.js proposals: installing the major
// its requirement names when nothing installed meets it (and it's
// supported), and moving it to the newest LTS when its major is older.
// build is true when no running process of the site was seen, so the
// upgrade changes what its deploy builds with.
func (c ChangeLink) nodeSiteLinks(org, host string, site report.Site, cycles []store.EOLCycle, now time.Time) (install, upgrade, newest string, build bool) {
	if c.ActionURL == "" || !validSiteRoot(site.Root) {
		return "", "", "", false
	}
	if site.NodeSatisfied != nil && !*site.NodeSatisfied && nodeMajorRe.MatchString(site.NodeWant) && nodeSupported(cycles, site.NodeWant, now) {
		install = c.actionLink("nodejs.install", org, host, url.Values{"major": {site.NodeWant}})
	}
	from := site.NodeWant
	if site.NodeBin != "" {
		from = report.NodeMajor(site.NodeVersion)
	}
	if nodeMajorRe.MatchString(from) {
		if newest = newestNodeLTS(cycles, from, now); newest != "" {
			upgrade = c.actionLink("nodejs.upgrade", org, host, url.Values{"from": {from}, "site": {site.Root}})
		}
	}
	return install, upgrade, newest, site.NodeBin == ""
}
