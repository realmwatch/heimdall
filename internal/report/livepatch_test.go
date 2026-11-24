// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"testing"

	"github.com/realmwatch/heimdall/internal/kernel"
	"github.com/realmwatch/heimdall/internal/store"
)

// A finding is live patched when it's on a kernel source, the running
// kernel's (not an old one's, not userland), and its advisory or a CVE is
// one the patch fixes.
func TestLivepatchedBy(t *testing.T) {
	fixes := []string{"CVE-2026-1234"}
	k := store.ReportFinding{AdvisoryID: "UBUNTU-CVE-2026-1234", CVEs: []string{"CVE-2026-1234"}, Package: "linux-aws-6.17"}
	for _, c := range []struct {
		name   string
		f      store.ReportFinding
		status string
		fixes  []string
		want   bool
	}{
		{"fixed by the patch", k, kernel.StatusRebootPending, fixes, true},
		{"by its advisory ID", store.ReportFinding{AdvisoryID: "CVE-2026-1234", Package: "linux"}, "", fixes, true},
		{"not in the patch", store.ReportFinding{AdvisoryID: "X", CVEs: []string{"CVE-2026-9999"}, Package: "linux"}, "", fixes, false},
		{"an old kernel's", k, kernel.StatusNotRunning, fixes, false},
		{"kernel userland", k, kernel.StatusUserland, fixes, false},
		{"not a kernel", store.ReportFinding{AdvisoryID: "X", CVEs: []string{"CVE-2026-1234"}, Package: "openssl"}, "", fixes, false},
		{"linux-firmware", store.ReportFinding{AdvisoryID: "X", CVEs: []string{"CVE-2026-1234"}, Package: "linux-firmware"}, "", fixes, false},
		{"no patch", k, "", nil, false},
	} {
		if got := livepatchedBy(c.fixes, c.f, c.status); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
