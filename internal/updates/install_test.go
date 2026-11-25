// SPDX-License-Identifier: AGPL-3.0-or-later

package updates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newInstaller(t *testing.T) *Installer {
	t.Helper()
	d := t.TempDir()
	status := filepath.Join(d, "status")
	if err := os.Mkdir(status, 0o750); err != nil {
		t.Fatal(err)
	}
	return &Installer{Current: "v0.5.0", Auto: true, Soak: 2 * time.Hour, Request: filepath.Join(d, "request"), Dir: status}
}

func TestInstallerRequests(t *testing.T) {
	i := newInstaller(t)
	for _, bad := range []string{"v0.4.9", "v0.5.0", "latest", "v0.6.0; rm -rf /"} {
		if err := i.Install(bad); err == nil {
			t.Errorf("Install(%q) accepted", bad)
		}
	}
	if err := i.Install("v0.6.0"); err != nil {
		t.Fatal(err)
	}
	if i.Requested() != "v0.6.0" || i.Pending() != "v0.6.0" {
		t.Fatalf("requested %q pending %q", i.Requested(), i.Pending())
	}
	if got, err := ReadRequest(i.Request); err != nil || got != "v0.6.0" {
		t.Fatalf("ReadRequest = %q, %v", got, err)
	}
	// Finished (either way): no longer pending.
	if err := WriteStatus(i.Dir, Status{Version: "v0.6.0", From: "v0.5.0", Result: ResultFailed, Message: "boom", Finished: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if i.Pending() != "" {
		t.Errorf("pending after it finished: %q", i.Pending())
	}
	if s, ok := i.Status(); !ok || s.Result != ResultFailed || s.Message != "boom" {
		t.Errorf("status = %+v, %v", s, ok)
	}
	// Not installed: no requests.
	os.RemoveAll(i.Dir)
	if err := i.Install("v0.6.0"); err != ErrNotReady {
		t.Errorf("without the service: %v", err)
	}
}

func TestReadRequestRefuses(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	os.WriteFile(target, []byte("v9.9.9\n"), 0o600)
	link := filepath.Join(d, "link")
	os.Symlink(target, link)
	if _, err := ReadRequest(link); err == nil {
		t.Error("followed a symlink")
	}
	junk := filepath.Join(d, "junk")
	os.WriteFile(junk, []byte(strings.Repeat("v1.2.3", 20)), 0o600)
	if _, err := ReadRequest(junk); err == nil {
		t.Error("accepted junk")
	}
	if _, err := ReadRequest(d); err == nil {
		t.Error("accepted a directory")
	}
}

func TestAutoReason(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	i := newInstaller(t)
	r := Release{Version: "v0.6.0", Published: now.Add(-time.Hour)}
	if why := i.AutoReason(r, now); !strings.Contains(why, "out for 2h") {
		t.Errorf("young release: %q", why)
	}
	r.Published = now.Add(-3 * time.Hour)
	if asked, err := i.Consider(r, now); err != nil || !asked || i.Requested() != "v0.6.0" {
		t.Fatalf("Consider = %v, %v (requested %q)", asked, err, i.Requested())
	}
	if why := i.AutoReason(r, now); !strings.Contains(why, "under way") {
		t.Errorf("while pending: %q", why)
	}
	// A failed release isn't retried on its own.
	WriteStatus(i.Dir, Status{Version: "v0.6.0", Result: ResultFailed, Finished: now})
	if why := i.AutoReason(r, now); !strings.Contains(why, "failed before") {
		t.Errorf("after a failure: %q", why)
	}
	// The next release is.
	if why := i.AutoReason(Release{Version: "v0.6.1", Published: now.Add(-3 * time.Hour)}, now); why != "" {
		t.Errorf("next release: %q", why)
	}
	i.Auto = false
	if why := i.AutoReason(r, now); why != "automatic install is off" {
		t.Errorf("off: %q", why)
	}
}
