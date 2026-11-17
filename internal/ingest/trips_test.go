// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// trip is a viti.trip.v1 line as the Laravel package writes it.
func trip(id, tripwire, severity string, at time.Time, extra string) string {
	return fmt.Sprintf(`{"schema":"viti.trip.v1","id":%q,"site":"app.example.com","root":"/home/web/app/current",`+
		`"tripwire":%q,"token":"/.env","severity":%q,"occurred_at":%q,"request":{"ip":"203.0.113.9","method":"GET",`+
		`"path":"/.env","query_keys":["x"],"headers":{"user-agent":"curl/8","cookie":"session=secret-cookie"%s}},`+
		`"actor":{"authenticated":false,"user_id":null},"context":{"ok":"yes","nested":{"secret":"secret-nested"}},"package_version":"v0.1.0"}`,
		id, tripwire, severity, at.UTC().Format(time.RFC3339), extra)
}

func TestParseTrips(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	body := strings.Join([]string{
		trip("01JD7Q3V9X8K2M4N6P0R2S4T6V", "decoy_routes", "noise", now, ""),
		trip("01JD7Q3V9X8K2M4N6P0R2S4T6V", "decoy_routes", "noise", now, ""),                       // duplicate
		trip("01JD7Q3V9X8K2M4N6P0R2S4T6W", "decoy_routes", "noise", now.Add(-31*24*time.Hour), ""), // too old
		trip("01JD7Q3V9X8K2M4N6P0R2S4T6X", "Bad Name", "high", now, ""),
		trip("01JD7Q3V9X8K2M4N6P0R2S4T6Y", "honey_user", "loud", now, ""),
		`not json`,
		strings.Replace(trip("01JD7Q3V9X8K2M4N6P0R2S4T6Z", "honey_user", "critical", now, ""), `"/.env"`, `"/x\u0007y"`, 1),
	}, "\n")

	got := parseTrips([]byte(body), now)
	if len(got) != 2 {
		t.Fatalf("parsed %d trips, want 2: %+v", len(got), got)
	}
	if got[1].Token != "/xy" || got[1].Severity != "critical" || got[0].IP != "203.0.113.9" {
		t.Errorf("trip fields: %+v", got[1])
	}
	// Only the allowlisted headers and scalar context survive.
	for _, tr := range got {
		if strings.Contains(tr.Detail, "secret-") {
			t.Errorf("detail kept a value outside the allowlist: %s", tr.Detail)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(tr.Detail), &d); err != nil || d["context"].(map[string]any)["ok"] != "yes" {
			t.Errorf("detail = %s (%v)", tr.Detail, err)
		}
	}
}

// The collector's spool, through collect.sh --push-trips, into the hub: only
// real trips are read and sent, a symlink or junk is deleted unread, trips
// are deleted once stored and kept while the hub can't take them (one
// from before trips answers 415).
func TestTripsFromCollector(t *testing.T) {
	sh, err := exec.LookPath("dash")
	if err != nil {
		if sh, err = exec.LookPath("sh"); err != nil {
			t.Skip("no POSIX shell")
		}
	}
	e := newEnv(t, nil)
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	os.Mkdir(spool, 0o755)
	tokenFile := filepath.Join(dir, "token")
	os.WriteFile(tokenFile, []byte(e.token+"\n"), 0o400)
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte(`{"schema":"viti.trip.v1","id":"secret-file"}`), 0o600)

	files := map[string]string{
		"01JD7Q3V9X8K2M4N6P0R2S4T6V.json": trip("01JD7Q3V9X8K2M4N6P0R2S4T6V", "honey_user", "critical", e.now, ""),
		"01JD7Q3V9X8K2M4N6P0R2S4T6W.json": trip("01JD7Q3V9X8K2M4N6P0R2S4T6W", "decoy_routes", "noise", e.now, ""),
		"01JD7Q3V9X8K2M4N6P0R2S4T6X.json": "junk",
		"notes.txt":                       "junk",
		".01JD7Q3V9X8K2M4N6P0R2S4T6Y.tmp": "still being written",
	}
	for name, body := range files {
		os.WriteFile(filepath.Join(spool, name), []byte(body), 0o644)
	}
	os.Symlink(secret, filepath.Join(spool, "01JD7Q3V9X8K2M4N6P0R2S4T6Z.json"))

	var up atomic.Bool
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() { // a hub from before trips: the body isn't a snapshot
			respond(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}
		e.h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	run := func() string {
		cmd := exec.Command(sh, collectSh, "--push-trips")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HEIMDALL_URL=" + srv.URL, "HEIMDALL_TOKEN_FILE=" + tokenFile,
			"HEIMDALL_TRIPS_SPOOL=" + spool, "HEIMDALL_ENV_FILE=/nonexistent"}
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	left := func() []string {
		ents, _ := os.ReadDir(spool)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return names
	}

	up.Store(false)
	if out := run(); !strings.Contains(out, "not sent") {
		t.Errorf("older hub: %q", out)
	}
	if l := left(); len(l) != 3 { // both trips, and the unfinished write
		t.Fatalf("older hub: spool has %v, want the 2 trips and the dot file", l)
	}

	up.Store(true)
	if out := run(); out != "" {
		t.Errorf("push-trips: %q", out)
	}
	if l := left(); len(l) != 1 || !strings.HasPrefix(l[0], ".") {
		t.Errorf("after the push the spool has %v, want only the unfinished write", l)
	}
	if b, _ := os.ReadFile(secret); !strings.Contains(string(b), "secret-file") {
		t.Error("the symlink's target was changed")
	}

	stored, err := e.st.RecentTrips(t.Context(), e.host.ID, 10)
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored %d trips (%v), want 2", len(stored), err)
	}
	for _, tr := range stored {
		if strings.Contains(fmt.Sprintf("%+v", tr), "secret-") {
			t.Errorf("stored a secret: %+v", tr)
		}
	}
	if got := e.anomalies(); len(got) != 1 || got[0] != "tripwire" { // the critical one; noise is only stored
		t.Errorf("anomalies = %v, want [tripwire]", got)
	}
}
