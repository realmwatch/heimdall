// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/feeds/eol"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// "Hand off PHP upgrade": an operator asks an Amp agent for the code side
// of moving a site to a newer PHP (handoff.BuildPHP), in two stages: make
// the repository run on both versions, then, once every site on it runs the
// new one, make it the minimum. A change-management tool does the server
// side (see "Propose PHP upgrade", changelink.go) and can link here with
// stage and to set. The page shows exactly the prompt; sending is a POST
// with the CSRF token and the prompt's digest, rate-limited per site and
// per repository, and audited as handoff.send with "kind": "php".

// phpHandoffURL is the confirm page for a site's PHP upgrade hand-off.
func phpHandoffURL(org, host, root, stage, to string) string {
	q := url.Values{"root": {root}}
	if stage != "" {
		q.Set("stage", stage)
	}
	if to != "" {
		q.Set("to", to)
	}
	return "/hosts/" + url.PathEscape(org) + "/" + url.PathEscape(host) + "/handoff/php?" + q.Encode()
}

// ampAgents are the Amp agents' names, the default first.
func ampAgents(agents []handoff.Agent) []string {
	var out []string
	for _, n := range agentNames(agents) {
		for _, a := range agents {
			if a.Name == n && a.IsAmp() {
				out = append(out, n)
			}
		}
	}
	return out
}

// phpSiteRow is one site on the repository, on the confirm page.
type phpSiteRow struct {
	Org, Host, Root, Name, URL, Label string
	Branch, PHP, Requirement          string
	This, Behind                      bool // Behind: runs an older PHP than a floor's target, or unknown
}

type phpHandoffBody struct {
	Org, Host, Root, Site, SiteURL string
	Agents                         []string
	Agent                          string
	As                             string
	CanPersonal, AmpKeys           bool
	Repo, RepoWeb                  string
	RepoManual                     bool
	Project, ProjectID             string
	ProjectNote                    string
	ProjectPicked                  bool
	Projects                       []handoffProject
	// Stage is handoff.PHPCompat or handoff.PHPFloor; From the site's PHP,
	// To the target and Tos the choices for it; Requirement composer.json's
	// require.php.
	Stage, From, To, Requirement string
	Tos                          []string
	Sites                        []phpSiteRow
	Behind                       int // a floor's sites on an older (or unknown) PHP
	// Where the pull request goes: the default branch, or one of the
	// sites' branches (Target "branch", TargetBranch).
	Branches             []string
	Target, TargetBranch string
	RepoBranch           string
	// Content is the prompt's text, File its data block.
	Content, File, FileName string
	Digest, RequestID       string
	Notice                  string
	// Blocked says why nothing can be sent (no newer PHP, a floor with
	// sites behind, PHP unknown); NeedRepo and NeedProject as on the
	// vulnerable-packages page.
	Blocked               string
	NeedRepo, NeedProject bool
}

// phpPlan is what a PHP hand-off's page and send settle on.
type phpPlan struct {
	stage, from, to string
	tos             []string
	rows            []phpSiteRow
	sites           []handoff.PHPSite
	branches        []string
	blocked         string
}

// loadPHPHandoff resolves a PHP upgrade hand-off: the site, an Amp agent
// (agentName, else the first Amp agent in default order), the sites that
// deploy its repository and the stage's target. ok is false for a 404.
func (s *server) loadPHPHandoff(ctx context.Context, v *auth.Viewer, org, host, root, agentName, as, stage, to string) (handoffTarget, phpPlan, bool, error) {
	var p phpPlan
	amps := ampAgents(s.cfg.Agents)
	if agentName == "" && len(amps) > 0 {
		agentName = amps[0]
	}
	if !slices.Contains(amps, agentName) {
		return handoffTarget{}, p, false, nil
	}
	t, ok, err := s.loadHandoff(ctx, v, org, host, root, agentName, as)
	if err != nil || !ok {
		return t, p, ok, err
	}
	switch stage {
	case "", handoff.PHPCompat:
		p.stage = handoff.PHPCompat
	case handoff.PHPFloor:
		p.stage = handoff.PHPFloor
	default:
		return t, p, false, nil
	}
	if to != "" && !handoff.PHPMinorRe.MatchString(to) {
		return t, p, false, nil
	}
	if err := s.phpRepoSites(ctx, v, t, &p); err != nil {
		return t, p, false, err
	}
	p.from = t.site.PHPFPM
	if !handoff.PHPMinorRe.MatchString(p.from) {
		p.from = ""
	}
	if p.stage == handoff.PHPCompat {
		if p.from == "" {
			p.blocked = "This site's PHP-FPM version isn't known, so there's nothing to upgrade from. The collector reads it from the site's PHP-FPM socket."
			return t, p, true, nil
		}
		cycles, err := s.st.EOLCycles(ctx, eol.ProductPHP)
		if err != nil {
			return t, p, false, err
		}
		p.tos = newerPHPs(cycles, p.from, s.now())
		// A target from a link (the change-management tool knows what the
		// server can install) is offered too, unless it's end-of-life.
		if to != "" && handoff.ComparePHP(to, p.from) > 0 && !slices.Contains(p.tos, to) && !phpEOL(cycles, to, s.now()) {
			p.tos = append(p.tos, to)
			slices.SortFunc(p.tos, func(a, b string) int { return handoff.ComparePHP(b, a) })
		}
		switch {
		case len(p.tos) == 0:
			p.blocked = "No PHP newer than " + p.from + " that still gets security fixes is known. Heimdall reads PHP's release cycles from endoflife.date."
		case to != "" && !slices.Contains(p.tos, to):
			p.blocked = "PHP " + to + " isn't a supported version newer than " + p.from + ". Pick one below."
			p.to = p.tos[0]
		case to != "":
			p.to = to
		default:
			p.to = p.tos[0]
		}
		return t, p, true, nil
	}
	// The floor: the target is the oldest PHP the repository's sites run,
	// unless the link named one; it's blocked while a site runs an older one.
	for _, r := range p.rows {
		if r.PHP != "" && (p.to == "" || handoff.ComparePHP(r.PHP, p.to) < 0) {
			p.to = r.PHP
		}
	}
	if to != "" {
		p.to = to
	}
	if p.to == "" {
		p.blocked = "None of the sites on this repository has a known PHP-FPM version, so there's no minimum to set."
		return t, p, true, nil
	}
	var behind []string
	for i := range p.rows {
		r := &p.rows[i]
		if r.PHP == "" || handoff.ComparePHP(r.PHP, p.to) < 0 {
			r.Behind = true
			behind = append(behind, r.Host+" · "+r.Name+" ("+cmp.Or(r.PHP, "unknown")+")")
		}
	}
	if len(behind) > 0 {
		p.blocked = "Not every site on this repository runs PHP " + p.to + " yet: " + strings.Join(behind, ", ") +
			". Raising the minimum first would make their next deploy fail. Switch them first (Propose PHP upgrade on each site's page)."
	}
	return t, p, true, nil
}

// phpEOL reports whether PHP version is known to be end-of-life.
func phpEOL(cycles []store.EOLCycle, version string, now time.Time) bool {
	for _, c := range cycles {
		if c.Cycle == version {
			return c.EOLReached || (c.EOL != nil && !c.EOL.After(now))
		}
	}
	return false
}

// phpRepoSites fills p's sites: t's own first, then the others that deploy
// its repository in orgs the viewer may operate in, with their branches
// and PHP versions.
func (s *server) phpRepoSites(ctx context.Context, v *auth.Viewer, t handoffTarget, p *phpPlan) error {
	labels, err := s.st.SiteLabelsByName(ctx)
	if err != nil {
		return err
	}
	add := func(org string, h report.Host, site report.Site, repo store.SiteRepo, this bool) {
		label, ok := labels[store.SiteLabelKey(org, h.Name, site.Root)]
		if !ok {
			label = suggestSiteLabel(site.ServerNames)
		}
		php := site.PHPFPM
		if !handoff.PHPMinorRe.MatchString(php) {
			php = ""
		}
		p.rows = append(p.rows, phpSiteRow{Org: org, Host: h.Name, Root: site.Root, Name: cmp.Or(siteName(site), site.Root),
			URL: siteURL(org, h.Name, site.Root), Label: label, Branch: repo.Branch(), PHP: php, Requirement: site.PHPRequirement, This: this})
		p.sites = append(p.sites, handoff.PHPSite{Host: h.Name, Site: siteName(site), SitePath: site.Root, Branch: repo.Branch(), PHP: php})
		if b := repo.Branch(); b != "" && !slices.Contains(p.branches, b) {
			p.branches = append(p.branches, b)
		}
	}
	add(t.host.OrgSlug, t.h, t.site, t.repo, true)
	key := handoff.RepoKey(t.repo.Repo())
	if key == "" {
		return nil
	}
	all, err := s.st.RepoSites(ctx)
	if err != nil {
		return err
	}
	byHost := map[string][]store.RepoSite{}
	var hosts []string
	for _, rs := range all {
		if handoff.RepoKey(rs.Repo.Repo()) != key || !v.Scope.CanView(rs.OrgID) || !s.canHandoff(v, rs.OrgID) ||
			rs.HostID == t.host.ID && rs.Root == t.site.Root {
			continue
		}
		k := rs.Org + "\x00" + rs.Host
		if byHost[k] == nil {
			hosts = append(hosts, k)
		}
		byHost[k] = append(byHost[k], rs)
	}
	slices.Sort(hosts)
	for _, k := range hosts {
		g := byHost[k]
		rep, err := report.Build(ctx, s.st, report.Filter{Org: g[0].Org, Host: g[0].Host, Scope: v.Scope}, s.now())
		if err != nil {
			return err
		}
		for _, rh := range rep.Hosts {
			if rh.Name != g[0].Host {
				continue
			}
			for _, rs := range g {
				for _, site := range rh.Sites {
					if site.Root == rs.Root {
						add(rs.Org, rh, site, rs.Repo, false)
					}
				}
			}
		}
	}
	slices.Sort(p.branches)
	return nil
}

// phpHandoffBody fills the confirm page; msg is zero when nothing can be
// sent.
func (s *server) phpHandoffBody(t handoffTarget, p phpPlan, msg handoff.Message, id string, target handoff.Target) phpHandoffBody {
	repo := t.repo.Repo()
	projects := make([]handoffProject, len(t.projects))
	for i, pr := range t.projects {
		projects[i] = handoffProject{ID: pr.ID, Ref: pr.Ref(), Repo: handoff.RepoShort(pr.RepositoryURL)}
	}
	behind := 0
	for _, r := range p.rows {
		if r.Behind {
			behind++
		}
	}
	tb := ""
	if target.Mode == handoff.TargetBranch {
		tb = target.Branches[0]
	}
	return phpHandoffBody{
		Org: t.host.OrgSlug, Host: t.host.Name, Root: t.site.Root, Site: siteName(t.site),
		SiteURL: siteURL(t.host.OrgSlug, t.host.Name, t.site.Root),
		Agents:  ampAgents(s.cfg.Agents), Agent: t.agent.Name,
		As: t.as, CanPersonal: t.canPersonal, AmpKeys: s.ampKeysOn(),
		Repo: repo, RepoWeb: handoff.WebURL(repo), RepoManual: t.repo.Manual != "",
		Project: t.project.Ref(), ProjectID: t.project.ID, ProjectPicked: t.projectPicked, ProjectNote: t.projectNote, Projects: projects,
		Stage: p.stage, From: p.from, To: p.to, Tos: p.tos, Requirement: t.site.PHPRequirement,
		Sites: p.rows, Behind: behind,
		Branches: p.branches, Target: cmp.Or(target.Mode, handoff.TargetDefault), TargetBranch: tb, RepoBranch: t.repoBranch,
		Content: msg.Content, File: string(msg.File), FileName: msg.FileName, Digest: msg.Digest, RequestID: id,
		Blocked: p.blocked,
	}
}

// phpTarget is where the pull request goes: the default branch, or one of
// the sites' branches. With none chosen, the repository's default target
// (store.RepoBranch) while it's one of them.
func phpTarget(t handoffTarget, p phpPlan, mode, branch string) (handoff.Target, bool) {
	if mode == "" {
		if t.repoBranch != "" && slices.Contains(p.branches, t.repoBranch) {
			return handoff.Target{Mode: handoff.TargetBranch, Branches: []string{t.repoBranch}}, true
		}
		return handoff.Target{Mode: handoff.TargetDefault}, true
	}
	tg, ok := handoffTargetOf(mode, branch, p.branches)
	if !ok || tg.Mode == handoff.TargetEach {
		return handoff.Target{Mode: handoff.TargetDefault}, false
	}
	return tg, true
}

func (s *server) phpHandoffMessage(t handoffTarget, p phpPlan, v *auth.Viewer, id string, target handoff.Target) (handoff.Message, error) {
	base := ""
	if target.Mode == handoff.TargetBranch {
		base = target.Branches[0]
	}
	return handoff.BuildPHP(t.agent, handoff.PHPRequest{
		Version: s.cfg.Version, Org: t.host.OrgSlug, Host: t.host.Name, Site: siteName(t.site), SitePath: t.site.Root,
		Repo: t.repo.Repo(), Stage: p.stage, From: p.from, To: p.to, Requirement: t.site.PHPRequirement, Base: base,
		Sites: p.sites, RequestID: id, RequestedBy: v.DisplayName,
		Link:       strings.TrimSuffix(s.cfg.BaseURL, "/") + siteURL(t.host.OrgSlug, t.host.Name, t.site.Root),
		AmpProject: t.project, AmpPersonal: t.as == asPersonal,
	})
}

// phpHandoffRender shows the confirm page, with the prompt when it can be
// sent.
func (s *server) phpHandoffRender(w http.ResponseWriter, r *http.Request, v *auth.Viewer, t handoffTarget, p phpPlan, target handoff.Target, notice string, status int) {
	id := handoff.RequestID()
	var msg handoff.Message
	body := phpHandoffBody{}
	if p.blocked == "" {
		var err error
		msg, err = s.phpHandoffMessage(t, p, v, id, target)
		switch {
		case errors.Is(err, handoff.ErrNoRepo), errors.Is(err, handoff.ErrNoProject):
			body = s.phpHandoffBody(t, p, handoff.Message{}, id, target)
			body.NeedRepo, body.NeedProject = errors.Is(err, handoff.ErrNoRepo), errors.Is(err, handoff.ErrNoProject)
		case err != nil:
			s.log.Warn("PHP hand-off can't be built", "host", t.host.Name, "site", t.site.Root, "err", err)
			p.blocked = "This hand-off can't be built from the site's data. The hub log has the details."
		}
	}
	if !body.NeedRepo && !body.NeedProject {
		body = s.phpHandoffBody(t, p, msg, id, target)
	}
	body.Notice = notice
	s.render(w, r, status, "phphandoff", v, "Hand off PHP upgrade", "sites", body)
}

// phpHandoffPage is the confirm step.
func (s *server) phpHandoffPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	q := r.URL.Query()
	t, p, ok, err := s.loadPHPHandoff(r.Context(), v, r.PathValue("org"), r.PathValue("host"), q.Get("root"), q.Get("agent"), q.Get("as"), q.Get("stage"), q.Get("to"))
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !ok {
		s.notFound(w, r, v)
		return
	}
	target, ok := phpTarget(t, p, q.Get("target"), q.Get("branch"))
	notice, status := "", http.StatusOK
	if !ok {
		notice, status = badTargetNotice, http.StatusBadRequest
	}
	s.phpHandoffRender(w, r, v, t, p, target, notice, status)
}

// phpHandoffSend starts the thread the operator confirmed.
func (s *server) phpHandoffSend(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	f := r.PostForm
	t, p, ok, err := s.loadPHPHandoff(r.Context(), v, r.PathValue("org"), r.PathValue("host"), f.Get("root"), f.Get("agent"), f.Get("as"), f.Get("stage"), f.Get("to"))
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !ok || f.Get("agent") == "" || f.Get("to") == "" {
		s.notFound(w, r, v)
		return
	}
	id := f.Get("request_id")
	if !handoff.ValidRequestID(id) {
		s.forbidden(w, r)
		return
	}
	target, ok := phpTarget(t, p, cmp.Or(f.Get("target"), handoff.TargetDefault), f.Get("branch"))
	if !ok {
		s.phpHandoffRender(w, r, v, t, p, target, badTargetNotice, http.StatusBadRequest)
		return
	}
	if p.blocked != "" || p.to != f.Get("to") {
		s.phpHandoffRender(w, r, v, t, p, target, "", http.StatusConflict)
		return
	}
	msg, err := s.phpHandoffMessage(t, p, v, id, target)
	if err != nil {
		s.phpHandoffRender(w, r, v, t, p, target, "", http.StatusBadRequest)
		return
	}
	if f.Get("digest") != msg.Digest {
		s.phpHandoffRender(w, r, v, t, p, target, "The prompt changed since you opened this page (the sites, their PHP or branches, the repository, Amp project or who it runs as). Check it again before sending.", http.StatusConflict)
		return
	}
	keys := []string{"php\x00site\x00" + strconv.FormatInt(t.host.ID, 10) + "\x00" + t.site.Root + "\x00" + t.agent.Name}
	if k := handoff.RepoKey(t.repo.Repo()); k != "" {
		keys = append(keys, "php\x00repo\x00"+k+"\x00"+t.agent.Name)
	}
	if i := s.handoffLimit.allow(s.now(), keys...); i >= 0 {
		notice := "This site's PHP upgrade was handed to " + t.agent.Name + " in the last few minutes. Try again later."
		if i == 1 {
			notice = "A PHP upgrade on " + handoff.RepoShort(t.repo.Repo()) + " was handed to " + t.agent.Name + " in the last few minutes. Try again later."
		}
		s.phpHandoffRender(w, r, v, t, p, target, notice, http.StatusTooManyRequests)
		return
	}
	thread, postErr := deliverHandoff(r.Context(), t.agent, msg)
	branches := target.Branches
	if branches == nil {
		branches = []string{}
	}
	detail := map[string]any{"agent": t.agent.Name, "host": t.host.Name, "site": t.site.Root, "request_id": id,
		"repo": t.repo.Repo(), "ok": postErr == nil, "kind": "php", "stage": p.stage, "from": p.from, "to": p.to,
		"target": target.Mode, "branches": branches, "sites": len(p.sites), "as": t.as}
	if thread != "" {
		detail["thread"] = thread
	}
	if postErr != nil {
		s.log.Warn("PHP hand-off not sent", "agent", t.agent.Name, "as", t.as, "host", t.host.Name, "site", t.site.Root, "err", postErr)
		detail["error"] = "send failed"
	}
	if err := s.st.Audit(r.Context(), store.AuditEntry{Actor: actorOf(v), Action: "handoff.send", OrgID: t.host.OrgID,
		Target: t.host.Name, Detail: detail, IP: clientIP(r)}); err != nil {
		s.log.Error("hand-off audit failed", "err", err)
	}
	result := "sent"
	if postErr != nil {
		result = "failed"
	} else if thread != "" {
		result += "&thread=" + thread
	}
	http.Redirect(w, r, siteURL(t.host.OrgSlug, t.host.Name, t.site.Root)+"&handoff="+result, http.StatusSeeOther)
}
