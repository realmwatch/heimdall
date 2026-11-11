// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

type plansBody struct {
	Plans      []store.Plan
	Orgs       []store.Org // orgs the viewer can create plans in
	CanAllOrgs bool
	Error      string
}

type planBody struct {
	Plan       store.Plan
	Items      []store.PlanItem
	Candidates []store.Host // visible hosts not yet in the plan
	CanOperate bool         // and the plan is open
	CanReopen  bool
	Error      string
	// Updates are the "Install updates on N hosts" links: one per batch
	// and org, for the hosts not yet done ([change_link] fleet_updates_url).
	Updates []planUpdates
}

type planUpdates struct {
	Batch int
	Org   string // shown only on a cross-org plan
	Hosts int
	URL   string
}

// planUpdateLinks groups the plan's hosts that aren't done yet by batch,
// then org (the tool links one org at a time), in at most fleetUpdatesMax
// hosts per link.
func planUpdateLinks(c ChangeLink, items []store.PlanItem) []planUpdates {
	if c.FleetUpdatesURL == "" {
		return nil
	}
	type key struct {
		batch int
		org   string
	}
	var order []key
	hosts := map[key][]string{}
	for _, it := range items {
		if !it.DoneAt.IsZero() {
			continue
		}
		k := key{it.Batch, it.Host.OrgSlug}
		if _, ok := hosts[k]; !ok {
			order = append(order, k)
		}
		hosts[k] = append(hosts[k], it.Host.Name)
	}
	slices.SortStableFunc(order, func(a, b key) int { return cmp.Or(cmp.Compare(a.batch, b.batch), cmp.Compare(a.org, b.org)) })
	var links []planUpdates
	for _, k := range order {
		for chunk := range slices.Chunk(hosts[k], fleetUpdatesMax) {
			links = append(links, planUpdates{Batch: k.batch, Org: k.org, Hosts: len(chunk), URL: c.fleetUpdatesLink(k.org, chunk)})
		}
	}
	return links
}

func (s *server) plansPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderPlans(w, r, v, http.StatusOK, "")
}

func (s *server) renderPlans(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, errMsg string) {
	plans, err := s.st.ListPlans(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := plansBody{Plans: plans, CanAllOrgs: v.Scope.Admin, Error: errMsg}
	for _, o := range orgs {
		if v.Scope.CanOperate(o.ID) {
			body.Orgs = append(body.Orgs, o)
		}
	}
	s.render(w, r, status, "plans", v, "Patch plans", "plans", body)
}

func (s *server) planCreate(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org := strings.TrimSpace(r.PostForm.Get("org"))
	if org != "" {
		host, err := s.orgBySlug(r, org)
		if err != nil || !v.Scope.CanOperate(host.ID) {
			s.renderPlans(w, r, v, http.StatusForbidden, "You can't create plans in that org.")
			return
		}
	} else if !v.Scope.Admin {
		s.renderPlans(w, r, v, http.StatusForbidden, "Only admins can create fleet-wide plans.")
		return
	}
	p, err := s.st.CreatePlan(r.Context(), actorOf(v), v.UserID, org, r.PostForm.Get("name"))
	if err != nil {
		s.renderPlans(w, r, v, http.StatusBadRequest, userError(err))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/plans/%d", p.ID), http.StatusSeeOther)
}

// plan loads a plan the viewer can see, or responds 404.
func (s *server) plan(w http.ResponseWriter, r *http.Request, v *auth.Viewer) (store.Plan, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		p, err := s.st.PlanByID(r.Context(), id)
		if err == nil && v.Scope.CanViewPlan(p) {
			return p, true
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, v, err)
			return store.Plan{}, false
		}
	}
	s.notFound(w, r, v)
	return store.Plan{}, false
}

func (s *server) planPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if p, ok := s.plan(w, r, v); ok {
		s.renderPlan(w, r, v, p, http.StatusOK, "")
	}
}

func (s *server) renderPlan(w http.ResponseWriter, r *http.Request, v *auth.Viewer, p store.Plan, status int, errMsg string) {
	items, err := s.st.PlanItems(r.Context(), p.ID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	in := map[int64]bool{}
	for _, it := range items {
		in[it.Host.ID] = true
	}
	hosts, err := s.visibleHosts(r, v, p.OrgSlug)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := planBody{Plan: p, Items: items, Error: errMsg,
		CanOperate: v.Scope.CanOperatePlan(p) && p.ClosedAt.IsZero(),
		CanReopen:  v.Scope.CanOperatePlan(p) && !p.ClosedAt.IsZero()}
	if body.CanOperate {
		body.Updates = planUpdateLinks(s.cfg.ChangeLink, items)
	}
	for _, h := range hosts {
		if !in[h.ID] {
			body.Candidates = append(body.Candidates, h)
		}
	}
	s.render(w, r, status, "plan", v, p.Name, "plans", body)
}

// planAction handles add, remove, done, undo and close.
func (s *server) planAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	p, ok := s.plan(w, r, v)
	if !ok {
		return
	}
	if !v.Scope.CanOperatePlan(p) {
		s.renderPlan(w, r, v, p, http.StatusForbidden, "You need the operator role to change this plan.")
		return
	}
	ctx, actor := r.Context(), actorOf(v)
	var err error
	if action := r.PathValue("action"); action == "close" || action == "reopen" {
		err = s.st.ClosePlan(ctx, actor, p.ID, action == "close", s.now())
	} else if action == "add" {
		err = s.planAddHosts(r, v, p, actor)
	} else {
		org, name := r.PostForm.Get("org"), r.PostForm.Get("host")
		var host store.IngestHost
		host, err = s.st.HostByName(ctx, org, name)
		if err == nil && !v.Scope.CanOperate(host.OrgID) {
			err = store.ErrNotFound
		}
		if err == nil {
			switch action {
			case "remove":
				err = s.st.RemoveFromPlan(ctx, actor, p.ID, host)
			case "done", "undo":
				err = s.st.SetPlanItemDone(ctx, actor, v.UserID, p.ID, host, action == "done", s.now())
			default:
				s.notFound(w, r, v)
				return
			}
		}
	}
	if err != nil {
		p, _ = s.st.PlanByID(ctx, p.ID)
		s.renderPlan(w, r, v, p, http.StatusBadRequest, userError(err))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/plans/%d", p.ID), http.StatusSeeOther)
}

// planAddHosts adds the add form's ticked "org/host" boxes to one batch.
func (s *server) planAddHosts(r *http.Request, v *auth.Viewer, p store.Plan, actor string) error {
	ctx := r.Context()
	refs := r.PostForm["hostref"]
	if len(refs) == 0 {
		return &store.ValidationError{Field: "host", Msg: "tick at least one"}
	}
	seen := make(map[string]bool, len(refs))
	hosts := make([]store.IngestHost, 0, len(refs))
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		org, name, _ := strings.Cut(ref, "/")
		host, err := s.st.HostByName(ctx, org, name)
		if err != nil {
			return err
		}
		if !v.Scope.CanOperate(host.OrgID) {
			return store.ErrNotFound
		}
		hosts = append(hosts, host)
	}
	batch, _ := strconv.Atoi(r.PostForm.Get("batch"))
	return s.st.AddHostsToPlan(ctx, actor, p.ID, hosts, max(batch, 1))
}

func (s *server) orgBySlug(r *http.Request, slug string) (store.Org, error) {
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return store.Org{}, err
	}
	for _, o := range orgs {
		if o.Slug == slug {
			return o, nil
		}
	}
	return store.Org{}, store.ErrNotFound
}

func actorOf(v *auth.Viewer) string { return fmt.Sprintf("user:%d", v.UserID) }

// userError shows validation and not-found errors; anything else is generic.
func userError(err error) string {
	var ve *store.ValidationError
	switch {
	case errors.As(err, &ve):
		return ve.Error()
	case errors.Is(err, store.ErrNotFound):
		return "Not found."
	case strings.Contains(err.Error(), "is closed"):
		return "This plan is closed."
	}
	return "Something went wrong; see the server log."
}
