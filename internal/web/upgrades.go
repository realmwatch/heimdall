// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/updates"
)

// Upgrades is Admin > Updates: the release check and the installer that
// hands upgrades to the root heimdall-upgrade service (updates/install.go).
type Upgrades struct {
	Checker   *updates.Checker
	Installer *updates.Installer
}

type updatesBody struct {
	Current   string
	Latest    *updates.Release // a newer release, if the last check found one
	Checked   *time.Time       // the last successful check, or nil
	Published *time.Time       // when Latest was published, or nil
	Started   *time.Time       // when the last upgrade started, or nil
	Ready     bool             // the root upgrade service is installed
	Auto      bool
	Soak      time.Duration
	AutoNote  string // why automatic install won't install Latest yet ("" when it will)
	Pending   string // the release asked for and not yet finished
	Status    *updates.Status
	Notice    string
	Error     string
}

var (
	updatesNotices = map[string]string{
		"checked":   "Checked GitHub for a newer release.",
		"requested": "Upgrade requested. The hub restarts when it's installed; this page shows how it went.",
	}
	updatesErrors = map[string]string{
		"check":   "Couldn't reach GitHub to check for a newer release. Try again later.",
		"install": "The upgrade couldn't be requested: it's no longer the newest release, or the upgrade service isn't installed.",
	}
)

func (s *server) updatesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	u := s.cfg.Upgrades
	if u == nil {
		s.notFound(w, r, v)
		return
	}
	body := updatesBody{Current: s.cfg.Version, Checked: timeOrNil(u.Checker.Checked()), Ready: u.Installer.Ready(),
		Auto: u.Installer.Auto, Soak: u.Installer.Soak, Pending: u.Installer.Pending(),
		Notice: updatesNotices[r.URL.Query().Get("ok")], Error: updatesErrors[r.URL.Query().Get("error")]}
	if rel, ok := u.Checker.Available(); ok {
		body.Latest, body.Published = &rel, timeOrNil(rel.Published)
		body.AutoNote = u.Installer.AutoReason(rel, s.now())
	}
	if st, ok := u.Installer.Status(); ok {
		body.Status, body.Started = &st, timeOrNil(st.Started)
	}
	s.render(w, r, http.StatusOK, "updates", v, "Updates", "updates", body)
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// updatesCheck asks GitHub for the latest release now.
func (s *server) updatesCheck(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	u := s.cfg.Upgrades
	if u == nil {
		s.notFound(w, r, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := u.Checker.Check(ctx); err != nil {
		s.log.Warn("update check", "err", err)
		http.Redirect(w, r, "/admin/updates?error=check", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/updates?ok=checked", http.StatusSeeOther)
}

// updatesInstall asks the root service to install the newer release the
// last check found (only that one: the form names it, so a stale page
// can't install something else).
func (s *server) updatesInstall(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	u := s.cfg.Upgrades
	if u == nil {
		s.notFound(w, r, v)
		return
	}
	rel, ok := u.Checker.Available()
	tag := r.PostForm.Get("version")
	if !ok || tag != rel.Version {
		http.Redirect(w, r, "/admin/updates?error=install", http.StatusSeeOther)
		return
	}
	if err := u.Installer.Install(tag); err != nil {
		s.log.Warn("upgrade request", "version", tag, "err", err)
		http.Redirect(w, r, "/admin/updates?error=install", http.StatusSeeOther)
		return
	}
	if err := s.st.Audit(r.Context(), store.AuditEntry{Actor: actorOf(v), Action: "hub.upgrade",
		Detail: map[string]any{"from": s.cfg.Version, "to": tag}}); err != nil {
		s.log.Warn("audit", "err", err)
	}
	http.Redirect(w, r, "/admin/updates?ok=requested", http.StatusSeeOther)
}
