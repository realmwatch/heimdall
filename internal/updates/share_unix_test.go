// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package updates

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// heimdall runs with umask 077; the status it records must still be
// readable by the hub's group.
func TestWriteStatusGroupReadable(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	if err := WriteStatus(dir, Status{Result: ResultRefused}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, statusFile))
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Mode().Perm(); m != 0o640 {
		t.Fatalf("status.json is %o, want 640", m)
	}
}
