// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/feeds/eol"
	"github.com/realmwatch/heimdall/internal/store"
)

// AptNodePath is where the nodejs package puts node.
const AptNodePath = "/usr/bin/node"

var (
	optNodeRe = regexp.MustCompile(`^/opt/node/[^/]+/bin/node$`)
	nvmNodeRe = regexp.MustCompile(`/\.nvm/versions/node/v[0-9.]+/bin/node$`)
)

// NodeKind is where a Node.js binary comes from: "opt" (/opt/node/<x>),
// "nvm", "apt" (/usr/bin/node, when the nodejs package is installed) or
// "other".
func NodeKind(path string, apt bool) string {
	switch {
	case path == AptNodePath && apt:
		return "apt"
	case optNodeRe.MatchString(path):
		return "opt"
	case nvmNodeRe.MatchString(path):
		return "nvm"
	}
	return "other"
}

// NodeHome is a Node.js binary's install prefix ("/opt/node/22" for
// /opt/node/22/bin/node), or its path when it isn't in a bin/.
func (r Runtime) NodeHome() string {
	if h, ok := strings.CutSuffix(r.Path, "/bin/node"); ok && h != "" {
		return h
	}
	return r.Path
}

// NodeInstall is one Node.js binary on a host, as the MCP host tool
// lists them (node_installs).
type NodeInstall struct {
	Path    string   `json:"path"`
	Version string   `json:"version"`
	Major   string   `json:"major,omitempty"`
	Kind    string   `json:"kind"` // apt, opt, nvm or other
	Running bool     `json:"running"`
	Sites   []string `json:"sites"`
}

// NodeInstalls is the host's Node.js binaries the collector reported
// (none from an older collector).
func (h Host) NodeInstalls() []NodeInstall {
	out := []NodeInstall{}
	for _, rt := range h.Runtimes {
		if rt.Name != eol.ProductNodeJS || rt.Path == "" {
			continue
		}
		sites := rt.Sites
		if sites == nil {
			sites = []string{}
		}
		out = append(out, NodeInstall{Path: rt.Path, Version: rt.Version, Major: NodeMajor(rt.Version), Kind: rt.Kind, Running: rt.Running, Sites: sites})
	}
	return out
}

// NodeMet is NodeSatisfied for templates: "yes", "no" or "" (unknown).
func (s Site) NodeMet() string {
	switch {
	case s.NodeSatisfied == nil:
		return ""
	case *s.NodeSatisfied:
		return "yes"
	}
	return "no"
}

// nodeRuntimes adds what the collector's X-Heimdall-Node said (n, zero
// for an older collector) to host: the apt nodejs runtime's path, use
// and whether it runs; a runtime for each other binary; and each site's
// Node. Run after the sites are built.
func nodeRuntimes(host *Host, n store.HostNode,
	lifecycle func(product, cycle string) (*Lifecycle, error), cycles func(string) ([]eol.Cycle, error)) error {
	if len(n.Bins) == 0 && len(n.Sites) == 0 {
		return nil
	}
	sitesOf := func(path string) []string {
		var out []string
		for root, s := range n.Sites {
			if s.Bin == path {
				out = append(out, root)
			}
		}
		slices.Sort(out)
		return out
	}
	bins := map[string]store.NodeBin{}
	for _, b := range n.Bins {
		bins[b.Path] = b
	}
	apt := ""
	for i := range host.Runtimes {
		rt := &host.Runtimes[i]
		if rt.Name != eol.ProductNodeJS || rt.Package == "" {
			continue
		}
		apt = rt.Version
		rt.Kind, rt.Path = "apt", AptNodePath
		rt.Running = bins[AptNodePath].Running
		rt.Sites = sitesOf(AptNodePath)
	}
	cs, err := cycles(eol.ProductNodeJS)
	if err != nil {
		return err
	}
	for _, b := range n.Bins {
		if b.Path == AptNodePath && apt != "" {
			continue
		}
		rt := Runtime{Name: eol.ProductNodeJS, Version: b.Version, Kind: NodeKind(b.Path, false), Path: b.Path,
			Running: b.Running, Sites: sitesOf(b.Path)}
		if cycle, ok := eol.RuntimeCycle(eol.ProductNodeJS, b.Version); ok {
			if rt.Life, err = lifecycle(eol.ProductNodeJS, cycle); err != nil {
				return err
			}
			for _, c := range cs {
				if c.Cycle == cycle && newerVersion(c.Latest, b.Version) {
					rt.Latest = c.Latest
					rt.Status = "outdated"
					rt.StatusNote = "Node.js " + c.Latest + " is out in this major"
				}
			}
		}
		if rt.Version == "" {
			rt.Version = "unknown"
		}
		host.Runtimes = append(host.Runtimes, rt)
	}
	// Each site's Node, and whether an installed one meets its requirement.
	var majors []int
	for _, rt := range host.Runtimes {
		if rt.Name == eol.ProductNodeJS {
			if m, ok := nodeMajor(rt.Version); ok {
				majors = append(majors, m)
			}
		}
	}
	for i := range host.Sites {
		site := &host.Sites[i]
		s, ok := n.Sites[site.Root]
		if !ok {
			continue
		}
		site.NodeBin, site.NodeRequirement = s.Bin, s.Requirement
		if s.Bin != "" {
			if s.Bin == AptNodePath && apt != "" {
				site.NodeVersion = apt
			} else {
				site.NodeVersion = bins[s.Bin].Version
			}
		}
		if r, ok := ParseNodeRange(s.Requirement); ok {
			met := slices.ContainsFunc(majors, r.Allows)
			site.NodeSatisfied = &met
			if m := r.Major(); m > 0 {
				site.NodeWant = strconv.Itoa(m)
			}
		}
	}
	return nil
}

// nodeMajor is a version's major ("22.11.0" → 22).
func nodeMajor(v string) (int, bool) {
	m, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), ".")
	n, err := strconv.Atoi(m)
	return n, err == nil && n > 0
}

// NodeMajor is a Node.js version's major as a string, or "".
func NodeMajor(v string) string {
	if m, ok := nodeMajor(v); ok {
		return strconv.Itoa(m)
	}
	return ""
}

// newerVersion reports whether dotted version a is newer than b; false
// when either doesn't parse.
func newerVersion(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		var err error
		if i < len(pa) {
			if x, err = strconv.Atoi(pa[i]); err != nil {
				return false
			}
		}
		if i < len(pb) {
			if y, err = strconv.Atoi(pb[i]); err != nil {
				return false
			}
		}
		if x != y {
			return x > y
		}
	}
	return false
}
