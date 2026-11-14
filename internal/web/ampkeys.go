// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
)

// "Your Amp key" (/account/amp): a user saves their own Amp API key, and
// the Amp hand-offs they start can run as them (their thread list, their
// plan's usage, their connected GitHub) instead of as the agent's
// service account, whose usage is the workspace's shared pool.
//
// The key is sealed with the hub's secrets key (Config.Secrets, the
// heimdall-secrets credential) and bound to the user's ID; it's opened
// only to run the CLI, never shown again, logged or audited. Saving one
// needs a fresh step-up, whatever the hub's step-up setting. Only the
// user themselves can save, test, use or remove it: no admin page shows
// or uses another user's key.

// PersonalAmp runs an Amp agent's CLI as one user, with their own key
// (cmd/heimdall's personalAmp). Tests fake it.
type PersonalAmp interface {
	// Starter starts threads and lists projects as the user: the agent's
	// CLI, the user's key, the user's own CLI home and project list.
	Starter(agent handoff.Agent, userID int64, key string) handoff.Starter
	// Check runs the CLI with the key without starting a thread. Its
	// error may carry the CLI's output (key masked), for the key's owner.
	Check(ctx context.Context, agent handoff.Agent, userID int64, key string) error
}

// ampKeyPurpose binds sealed Amp keys (secret.Sealer).
const ampKeyPurpose = "amp-key"

// Amp keys are checked loosely: Amp's start sgamp_, but a key that
// doesn't is saved with a note.
const (
	ampKeyMin    = 20
	ampKeyMax    = 512
	ampKeyPrefix = "sgamp_"
)

// ampKeyCheckTimeout bounds Test.
const ampKeyCheckTimeout = time.Minute

// ampKeyAgent is the Amp agent whose CLI a personal key runs: the default
// agent if it's an Amp one, else the first. ok is false with none.
func (s *server) ampKeyAgent() (handoff.Agent, bool) {
	if def, ok := handoff.DefaultAgent(s.cfg.Agents); ok && def.IsAmp() {
		return def, true
	}
	for _, a := range s.cfg.Agents {
		if a.IsAmp() {
			return a, true
		}
	}
	return handoff.Agent{}, false
}

// ampKeysOn: personal Amp keys can be saved and used: an Amp agent is
// configured and the secrets key is loaded.
func (s *server) ampKeysOn() bool {
	_, amp := s.ampKeyAgent()
	return amp && s.cfg.Secrets != nil && s.cfg.PersonalAmp != nil
}

// ampKeyNav: the viewer gets the "Amp key" link: personal keys are on
// and they can hand off somewhere, or they're an admin and an Amp agent
// is configured (the page then says how to turn keys on).
func (s *server) ampKeyNav(v *auth.Viewer) bool {
	if v == nil || s.cfg.PersonalAmp == nil {
		return false
	}
	if _, amp := s.ampKeyAgent(); !amp {
		return false
	}
	return v.IsAdmin || s.cfg.Secrets != nil && canOperateAny(v)
}

// errAmpKeyUnreadable: a saved key that doesn't open with this hub's
// secrets key (it was replaced, say); it's as good as none.
var errAmpKeyUnreadable = errors.New("saved Amp key can't be opened with this hub's secrets key")

// personalAmpKey is a user's own Amp key, opened for use now, and its
// sealed form; "" when they have none or keys are off.
func (s *server) personalAmpKey(ctx context.Context, userID int64) (key string, sealed []byte, err error) {
	if !s.ampKeysOn() || userID <= 0 {
		return "", nil, nil
	}
	k, ok, err := s.st.AmpKeyOf(ctx, userID)
	if err != nil || !ok {
		return "", nil, err
	}
	b, err := s.cfg.Secrets.Open(ampKeyPurpose, userID, k.Sealed)
	if err != nil {
		return "", nil, errAmpKeyUnreadable
	}
	return string(b), k.Sealed, nil
}

// cleanAmpKey drops what copying a key tends to add: spaces and line
// breaks anywhere in it (a wrapped key), and invisible format characters
// such as zero-width spaces. A key itself never has any.
func cleanAmpKey(raw string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, raw)
}

// validAmpKey checks a pasted (cleaned) key loosely: one token of
// printable ASCII. When it isn't one, why is "short", "long" or "char",
// and n is its length, or the 1-based position of the first character
// that can't be in a key. note is set for one that doesn't look like Amp's.
func validAmpKey(key string) (note, why string, n int, ok bool) {
	switch {
	case len(key) < ampKeyMin:
		return "", "short", len(key), false
	case len(key) > ampKeyMax:
		return "", "long", len(key), false
	}
	for i, r := range key {
		if r <= ' ' || r > '~' {
			return "", "char", utf8.RuneCountInString(key[:i]) + 1, false
		}
	}
	if !strings.HasPrefix(key, ampKeyPrefix) {
		note = "Amp's API keys usually start with " + ampKeyPrefix + "; check you copied the whole key, then Test it."
	}
	return note, "", 0, true
}

// ampKeyInvalid says why a pasted key was refused, from fixed text and a
// number only: never any of the key.
func ampKeyInvalid(why, n string) string {
	k, err := strconv.Atoi(n)
	if err != nil || k < 0 || k > 1<<20 {
		return ampKeyNotices["invalid"]
	}
	switch why {
	case "short":
		return fmt.Sprintf("That key is only %d characters: Amp's are longer. Copy the whole key and paste it again.", k)
	case "long":
		return fmt.Sprintf("That's %d characters, more than an API key (at most %d). Paste only the key.", k, ampKeyMax)
	case "char":
		return fmt.Sprintf("Character %d of what you pasted can't be in an API key (keys are plain letters, digits and symbols). Copy the key again, ideally with Amp's copy button.", k)
	}
	return ampKeyNotices["invalid"]
}

// ampKeyHint is a key's last four characters.
func ampKeyHint(key string) string { return key[max(0, len(key)-4):] }

type ampKeyBody struct {
	On         bool // personal keys can be saved (the secrets key is loaded)
	Agent      string
	Saved      bool
	Hint       string
	SavedAt    template.HTML
	TestedAt   template.HTML // "" until a Test worked
	Unreadable bool          // saved, but it can't be opened any more
	Fresh      bool          // stepped up: the key form is shown
	Notice     string
	Error      string
	// Test's result: TestOK, or TestFail with the CLI's reason.
	TestOK   bool
	TestFail string
}

var ampKeyNotices = map[string]string{
	"saved":   "Saved. Use Test to check it works.",
	"removed": "Removed. Your hand-offs run as the service account again. If you no longer use that key anywhere, revoke it in Amp too.",
	"none":    "There's no saved key to remove.",
	"expired": "That took more than five minutes since you confirmed it's you. Confirm again, then save the key.",
	"invalid": "That doesn't look like an API key: paste the whole key, with no spaces (20 to 512 characters).",
}

func (s *server) ampKeyBody(r *http.Request, v *auth.Viewer) (ampKeyBody, error) {
	body := ampKeyBody{On: s.ampKeysOn(), Fresh: v.Fresh(s.now())}
	if a, ok := s.ampKeyAgent(); ok {
		body.Agent = a.Name
	}
	if !body.On {
		return body, nil
	}
	k, ok, err := s.st.AmpKeyOf(r.Context(), v.UserID)
	if err != nil || !ok {
		return body, err
	}
	body.Saved, body.Hint, body.SavedAt = true, k.Hint, dateHTML(k.CreatedAt)
	if !k.TestedAt.IsZero() {
		body.TestedAt = dayAgoHTML(&k.TestedAt, s.now())
	}
	if _, err := s.cfg.Secrets.Open(ampKeyPurpose, v.UserID, k.Sealed); err != nil {
		body.Unreadable = true
	}
	return body, nil
}

// ampKeyPage is GET /account/amp.
func (s *server) ampKeyPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.ampKeyNav(v) {
		s.notFound(w, r, v)
		return
	}
	body, err := s.ampKeyBody(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	q := r.URL.Query()
	body.Notice = ampKeyNotices[q.Get("ok")]
	if q.Get("ok") == "invalid" && q.Get("why") != "" {
		body.Notice = ampKeyInvalid(q.Get("why"), q.Get("n"))
	}
	if q.Get("ok") == "saved" && q.Get("note") == "prefix" {
		body.Notice += " Amp's API keys usually start with " + ampKeyPrefix + ": check you copied the whole key."
	}
	s.renderAmpKey(w, r, v, http.StatusOK, body)
}

func (s *server) renderAmpKey(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, body ampKeyBody) {
	s.render(w, r, status, "ampkey", v, "Amp key", "ampkey", body)
}

// ampKeyConfirm is POST /account/amp/confirm: always behind a step-up
// (alwaysStepPaths), so getting here means the viewer just proved it's
// them; the page then shows the key form. The key itself is never part
// of a step-up prompt's carried form.
func (s *server) ampKeyConfirm(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.ampKeysOn() || !s.ampKeyNav(v) {
		s.notFound(w, r, v)
		return
	}
	http.Redirect(w, r, "/account/amp#key", http.StatusSeeOther)
}

// ampKeySave is POST /account/amp/save: seal and store the viewer's key.
// The session must have stepped up in the last few minutes.
func (s *server) ampKeySave(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.ampKeysOn() || !s.ampKeyNav(v) {
		s.notFound(w, r, v)
		return
	}
	if !v.Fresh(s.now()) {
		http.Redirect(w, r, "/account/amp?ok=expired#key", http.StatusSeeOther)
		return
	}
	key := cleanAmpKey(r.PostForm.Get("key"))
	note, why, n, ok := validAmpKey(key)
	if !ok {
		http.Redirect(w, r, "/account/amp?ok=invalid&why="+why+"&n="+strconv.Itoa(n)+"#key", http.StatusSeeOther)
		return
	}
	sealed := s.cfg.Secrets.Seal(ampKeyPurpose, v.UserID, []byte(key))
	if err := s.st.SetAmpKey(r.Context(), actorOf(v), v.UserID, sealed, ampKeyHint(key), s.now()); err != nil {
		s.fail(w, r, v, err)
		return
	}
	next := "/account/amp?ok=saved"
	if note != "" {
		next += "&note=prefix"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ampKeyTest is POST /account/amp/test: run the CLI with the viewer's
// saved key, without starting a thread, and show what happened.
func (s *server) ampKeyTest(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	agent, _ := s.ampKeyAgent()
	if !s.ampKeysOn() || !s.ampKeyNav(v) {
		s.notFound(w, r, v)
		return
	}
	key, sealed, err := s.personalAmpKey(r.Context(), v.UserID)
	if err != nil && !errors.Is(err, errAmpKeyUnreadable) {
		s.fail(w, r, v, err)
		return
	}
	body, berr := s.ampKeyBody(r, v)
	if berr != nil {
		s.fail(w, r, v, berr)
		return
	}
	if key == "" {
		body.Error = "There's no saved key to test."
		if errors.Is(err, errAmpKeyUnreadable) {
			body.Error = "Your saved key can't be read on this hub any more. Remove it and save it again."
		}
		s.renderAmpKey(w, r, v, http.StatusBadRequest, body)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ampKeyCheckTimeout)
	defer cancel()
	if err := s.cfg.PersonalAmp.Check(ctx, agent, v.UserID, key); err != nil {
		// The reason goes to the key's owner only (masked by the CLI
		// runner, escaped by the template), and to nobody's log.
		body.TestFail = capText(strings.ReplaceAll(err.Error(), key, "[key]"), 600)
		s.log.Warn("personal Amp key test failed", "user", v.UserID)
		s.renderAmpKey(w, r, v, http.StatusOK, body)
		return
	}
	if err := s.st.AmpKeyTested(r.Context(), v.UserID, sealed, s.now()); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if body, err = s.ampKeyBody(r, v); err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.TestOK = true
	s.renderAmpKey(w, r, v, http.StatusOK, body)
}

// ampKeyRemove is POST /account/amp/remove. It needs no step-up: it only
// takes access away. It works even when keys are off, so a key saved
// before can always be removed.
func (s *server) ampKeyRemove(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.ampKeyNav(v) {
		s.notFound(w, r, v)
		return
	}
	removed, err := s.st.DeleteAmpKey(r.Context(), actorOf(v), v.UserID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !removed {
		http.Redirect(w, r, "/account/amp?ok=none", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/amp?ok=removed", http.StatusSeeOther)
}

// capText is s cut to n bytes (at a rune boundary), with "…".
func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
