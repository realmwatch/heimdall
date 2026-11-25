// SPDX-License-Identifier: AGPL-3.0-or-later

package updates

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Upgrading the hub from the UI, or on its own.
//
// The hub runs unprivileged and can't replace its own binary. It only
// writes the release it wants to RequestPath. A root systemd path unit,
// heimdall-upgrade.path (installed by install-hub.sh), starts
// heimdall-upgrade.service, which runs `heimdall upgrade --request`: that
// reads the version, refuses anything but a newer vX.Y.Z, verifies the
// release's Sigstore signature and checksums, and runs its install-hub.sh
// (which keeps the previous binary and database and rolls back if the new
// hub doesn't come up). It writes how it went to StatusDir, which root
// owns and the hub can only read. So the most a compromised hub can do is
// ask for a genuine, newer, signed release.

// Where the hub and the root service meet.
const (
	RequestPath = "/var/lib/heimdall/upgrade-request" // the hub's own data folder
	StatusDir   = "/var/lib/heimdall-upgrade"         // root:heimdall-hub 0750
	statusFile  = "status.json"
	logFile     = "upgrade.log"
)

// Upgrade results.
const (
	ResultRunning = "running"
	ResultOK      = "ok"
	ResultFailed  = "failed"
	ResultRefused = "refused"
)

// Status is what the root service last did.
type Status struct {
	Version  string    `json:"version"`  // the release it was asked for
	From     string    `json:"from"`     // the release it upgraded from
	Result   string    `json:"result"`   // ResultRunning, ResultOK, ResultFailed or ResultRefused
	Message  string    `json:"message"`  // why, for failed or refused
	Started  time.Time `json:"started"`  // when it started
	Finished time.Time `json:"finished"` // zero while running
	Log      string    `json:"-"`        // the end of the installer's output
}

// Installer asks the root service for upgrades and reports how they went.
type Installer struct {
	Current string        // this build's version
	Auto    bool          // install newer releases without a click
	Soak    time.Duration // how long a release must have been out before Auto installs it
	Request string        // RequestPath if empty
	Dir     string        // StatusDir if empty

	mu sync.Mutex
}

func (i *Installer) request() string {
	if i.Request != "" {
		return i.Request
	}
	return RequestPath
}

func (i *Installer) dir() string {
	if i.Dir != "" {
		return i.Dir
	}
	return StatusDir
}

// Ready reports whether the root service is installed: install-hub.sh
// creates StatusDir along with it.
func (i *Installer) Ready() bool {
	st, err := os.Stat(i.dir())
	return err == nil && st.IsDir()
}

// ErrNotReady means the root upgrade service isn't installed on this hub.
var ErrNotReady = errors.New("the upgrade service isn't installed on this hub; run sudo heimdall upgrade once to install it")

// Install asks the root service to upgrade to tag, which must be a newer
// release than this one.
func (i *Installer) Install(tag string) error {
	if !IsTag(tag) || !Newer(tag, i.Current) {
		return fmt.Errorf("%q isn't a newer release than %s", tag, i.Current)
	}
	if !i.Ready() {
		return ErrNotReady
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	// Written in place (not renamed): the path unit fires when it's closed
	// after writing.
	return os.WriteFile(i.request(), []byte(tag+"\n"), 0o600)
}

// Requested is the release last asked for, or "".
func (i *Installer) Requested() string {
	b, err := os.ReadFile(i.request())
	if err != nil {
		return ""
	}
	if t := strings.TrimSpace(string(b)); IsTag(t) {
		return t
	}
	return ""
}

// Status is what the root service last did, if anything.
func (i *Installer) Status() (Status, bool) {
	b, err := os.ReadFile(filepath.Join(i.dir(), statusFile))
	if err != nil {
		return Status{}, false
	}
	var s Status
	if json.Unmarshal(b, &s) != nil {
		return Status{}, false
	}
	if f, err := os.Open(filepath.Join(i.dir(), logFile)); err == nil {
		defer f.Close()
		const tail = 8 << 10
		if st, err := f.Stat(); err == nil && st.Size() > tail {
			f.Seek(st.Size()-tail, io.SeekStart)
		}
		b, _ := io.ReadAll(io.LimitReader(f, 8<<10))
		s.Log = string(b)
	}
	return s, true
}

// Pending reports whether an upgrade was asked for and hasn't finished:
// the request is newer than this build, and the service hasn't finished
// with it.
func (i *Installer) Pending() string {
	req := i.Requested()
	if req == "" || !Newer(req, i.Current) {
		return ""
	}
	if s, ok := i.Status(); ok && s.Version == req && s.Result != ResultRunning && !s.Finished.IsZero() {
		return ""
	}
	return req
}

// AutoReason says why Auto won't install r yet ("" when it will).
func (i *Installer) AutoReason(r Release, now time.Time) string {
	switch {
	case !i.Auto:
		return "automatic install is off"
	case r.Version == "" || !Newer(r.Version, i.Current):
		return "no newer release"
	case !i.Ready():
		return "the upgrade service isn't installed"
	case i.Pending() != "":
		return "an upgrade is already under way"
	}
	if s, ok := i.Status(); ok && s.Version == r.Version && (s.Result == ResultFailed || s.Result == ResultRefused) {
		return "it failed before; install it by hand once the problem is fixed"
	}
	if !r.Published.IsZero() && now.Sub(r.Published) < i.Soak {
		return "waiting until it has been out for " + i.Soak.String()
	}
	return ""
}

// Consider installs r if Auto says to. It returns whether it asked.
func (i *Installer) Consider(r Release, now time.Time) (bool, error) {
	if i.AutoReason(r, now) != "" {
		return false, nil
	}
	return true, i.Install(r.Version)
}

// ── The root side (heimdall upgrade --request) ─────────────────────────────

// ReadRequest reads a request file as root: a regular file (never a
// symlink: the folder is the hub's), small, holding one vX.Y.Z.
func ReadRequest(path string) (string, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("the request isn't a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return "", err
	}
	tag := string(bytes.TrimSpace(b))
	if !IsTag(tag) {
		return "", fmt.Errorf("the request %q isn't a release tag", tag)
	}
	return tag, nil
}

// WriteStatus records s in dir (root-owned), replacing the file whole.
func WriteStatus(dir string, s Status) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, statusFile+".tmp")
	os.Remove(tmp)
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	ShareWithHub(dir, tmp)
	return os.Rename(tmp, filepath.Join(dir, statusFile))
}

// ShareWithHub gives a file in dir dir's group (heimdall-hub) and makes it
// group-readable, so the hub can read it: root's files are otherwise root's
// group, and heimdall's umask (077) leaves them 0600.
func ShareWithHub(dir, path string) {
	os.Chmod(path, 0o640)
	if g := groupOf(dir); g >= 0 {
		os.Chown(path, -1, g)
	}
}

// LogPath is where the root service keeps the installer's output.
func LogPath(dir string) string { return filepath.Join(dir, logFile) }
