// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// Retiring a site: an operator archives it (intent, kept by Heimdall),
// and the change-management tool's site.disable takes its nginx vhost,
// workers and scheduled jobs out of service without deleting anything.
// The collector then lists it as disabled (X-Heimdall-Sites) and leaves it
// out of the snapshot, so it has no findings and uses no PHP. An archived,
// disabled site is hidden by default.

// disabledSite is a site whose nginx vhost is there but not enabled.
type disabledSite struct {
	Org, Host  string
	Root       string
	Vhost      string // "" when the collector couldn't name it
	Names      []string
	Archived   bool
	CanOperate bool
	EnableURL  string // drafts site.enable (changelink.go)
	Back       string // where the archive form returns to
}

// siteDisableLink drafts site.disable for a site: the tool's agent takes
// the vhost out of service, stops the site's workers, units and scheduled
// jobs, and deletes nothing. vhost is a hint the agent checks.
func (c ChangeLink) siteDisableLink(org, host, root, vhost string) string {
	return c.actionLink("site.disable", org, host, siteParams(root, vhost))
}

// siteEnableLink drafts site.enable, which undoes site.disable.
func (c ChangeLink) siteEnableLink(org, host, root, vhost string) string {
	return c.actionLink("site.enable", org, host, siteParams(root, vhost))
}

func siteParams(root, vhost string) url.Values {
	p := url.Values{"root": {root}}
	if vhost != "" {
		p.Set("vhost", vhost)
	}
	return p
}

// siteArchiveNotices are the fixed notices after archiving.
var siteArchiveNotices = map[string]string{
	"archived":   "Site archived. Once its vhost is disabled, it's hidden from the site lists.",
	"unarchived": "Site no longer archived.",
}

// hostDisabledSites are a host's disabled sites, with the archived ones
// left out unless show; hidden counts those left out.
func (s *server) hostDisabledSites(org, host string, vhosts map[string]store.SiteVhost,
	archived map[string]store.SiteArchive, canOperate, show bool) (out []disabledSite, hidden int) {
	back := hostURL(org, host) + "#disabled-sites"
	if show {
		back = hostURL(org, host) + "?archived=1#disabled-sites"
	}
	for _, d := range sortedVhosts(vhosts) {
		if d.Enabled {
			continue
		}
		_, arch := archived[store.SiteLabelKey(org, host, d.Root)]
		if arch && !show {
			hidden++
			continue
		}
		out = append(out, disabledSite{Org: org, Host: host, Root: d.Root, Vhost: d.Vhost, Names: d.Names,
			Archived: arch, CanOperate: canOperate, EnableURL: s.cfg.ChangeLink.siteEnableLink(org, host, d.Root, d.Vhost), Back: back})
	}
	return out, hidden
}

func sortedVhosts(m map[string]store.SiteVhost) []store.SiteVhost {
	out := make([]store.SiteVhost, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b store.SiteVhost) int { return strings.Compare(a.Root, b.Root) })
	return out
}

// siteArchive archives a site or brings it back (operators only).
func (s *server) siteArchive(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PostForm.Get("org"), r.PostForm.Get("host"))
	if err != nil || !v.Scope.CanOperate(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	archive := r.PostForm.Get("archive") == "1"
	back := "/sites"
	if b := r.PostForm.Get("back"); strings.HasPrefix(b, "/hosts/") || strings.HasPrefix(b, "/sites") {
		back = safeNext(b)
	}
	var verr *store.ValidationError
	switch err := s.st.SetSiteArchived(r.Context(), actorOf(v), host.ID, r.PostForm.Get("root"), archive); {
	case errors.As(err, &verr):
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	case err != nil:
		s.fail(w, r, v, err)
		return
	}
	note := "unarchived"
	if archive {
		note = "archived"
	}
	back, frag, _ := strings.Cut(back, "#")
	sep := "?"
	if strings.Contains(back, "?") {
		sep = "&"
	}
	back += sep + "site_archive=" + note
	if frag != "" {
		back += "#" + frag
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// siteRows are the sites list's rows: every reported site, plus the
// disabled ones (no snapshot data), with their archive state and links.
func (s *server) siteRows(ctx context.Context, v *auth.Viewer, org string, rep *report.Report) ([]siteRow, error) {
	archived, err := s.st.ArchivedSites(ctx)
	if err != nil {
		return nil, err
	}
	vhosts, err := s.st.AllSiteVhosts(ctx)
	if err != nil {
		return nil, err
	}
	var all []siteRow
	served := map[string]bool{}
	for _, h := range rep.Hosts {
		for _, site := range h.Sites {
			key := store.SiteLabelKey(h.Org, h.Name, site.Root)
			served[key] = true
			row := siteRow{Site: site, Org: h.Org, Host: h.Name}
			if _, row.Archived = archived[key]; row.Archived && site.WebServer == "nginx" {
				row.DisableURL = s.cfg.ChangeLink.siteDisableLink(h.Org, h.Name, site.Root, vhosts[key].Vhost)
			}
			all = append(all, row)
		}
	}
	for key, d := range vhosts {
		if d.Enabled || served[key] || !v.Scope.CanView(d.OrgID) || (org != "" && d.Org != org) {
			continue
		}
		row := siteRow{Site: report.Site{Root: d.Root, ServerNames: d.Names, WebServer: "nginx"}, Org: d.Org, Host: d.Host,
			Disabled: true, EnableURL: s.cfg.ChangeLink.siteEnableLink(d.Org, d.Host, d.Root, d.Vhost)}
		_, row.Archived = archived[key]
		all = append(all, row)
	}
	return all, nil
}
