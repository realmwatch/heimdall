// SPDX-License-Identifier: AGPL-3.0-or-later

package leftovers

import (
	"slices"
	"strings"
)

// Step is one thing to do about a host's leftovers, in order, with the
// packages it's about. Steps restate the Finding for people: they add no
// facts of their own, beyond guessing (FromSource) which stale source a
// package came from.
type Step struct {
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Packages []string `json:"packages,omitempty"`
	// Waiting: the step is for after the others (packages to decide on
	// once the steps before have run and the server has reported again).
	Waiting bool `json:"waiting,omitempty"`
}

// sourceMarkers tie a package's version to the repository that builds
// it: a version naming the marker most likely came from a source whose
// URI holds one of the hints.
var sourceMarkers = []struct {
	marker string
	hints  []string
}{
	{"sury", []string{"sury", "ondrej"}},
	{"pgdg", []string{"postgresql"}},
	{"nodesource", []string{"nodesource"}},
	{"mariadb", []string{"mariadb"}},
	{"nginx", []string{"nginx.org", "ondrej/nginx"}},
}

// FromSource is the stale source a package most likely came from, by its
// version's builder marker, or nil.
func FromSource(f *Finding, version string) *StaleSource {
	v := strings.ToLower(version)
	for _, m := range sourceMarkers {
		if !strings.Contains(v, m.marker) {
			continue
		}
		for i := range f.Sources {
			uri := strings.ToLower(f.Sources[i].URI)
			if slices.ContainsFunc(m.hints, func(h string) bool { return strings.Contains(uri, h) }) {
				return &f.Sources[i]
			}
		}
	}
	return nil
}

// Steps turns a Finding into what to do, in order: fix the sources,
// reinstall what's still built for the old release, replace, restart,
// remove, and last the packages to decide on once the rest is done.
func Steps(f *Finding) []Step {
	if f == nil {
		return nil
	}
	cn := f.Codename
	var out []Step
	fromSource := map[string]*StaleSource{}
	for _, l := range slices.Concat(f.Obsolete, f.OldBuilds) {
		if s := FromSource(f, l.Version); s != nil {
			fromSource[l.Name] = s
		}
	}
	if len(f.Sources) > 0 {
		var files []string
		for _, s := range f.Sources {
			files = append(files, "/etc/apt/"+s.File+" ("+s.Suite+" → "+s.Current+")")
		}
		var pkgs []string
		for _, l := range slices.Concat(f.Obsolete, f.OldBuilds) {
			if fromSource[l.Name] != nil {
				pkgs = append(pkgs, l.Name)
			}
		}
		d := "Point each at " + cn + "'s suite if the repository publishes one, otherwise disable it, then run apt update: " +
			strings.Join(files, "; ") + "."
		if len(pkgs) > 0 {
			d += " The packages listed most likely came from these sources: once apt sees " + cn +
				"'s builds of them, most of the steps below become simple replacements. Let the server report again before going on."
		}
		out = append(out, Step{Title: "Fix the apt sources that name an older release", Detail: d, Packages: pkgs})
	}
	if names := names(f.OldBuilds, nil); len(names) > 0 {
		out = append(out, Step{Title: "Reinstall what's still built for an older release",
			Detail:   "Install " + cn + "'s build of each (apt install --reinstall, or the " + cn + " package of the same name), so they get " + cn + "'s security fixes.",
			Packages: names})
	}
	plan := func(p string) []string {
		return names(f.Obsolete, func(l Leftover) bool { return l.Plan == p })
	}
	if names := plan(PlanReplace); len(names) > 0 {
		out = append(out, Step{Title: "Replace these with " + cn + "'s build",
			Detail:   cn + "'s sources have a package of the same name. Install it in place of the old one (apt install --allow-downgrades <package>=<the version apt-cache policy offers>); what needs it keeps working.",
			Packages: names})
	}
	if len(f.UsedBy) > 0 {
		var units, pkgs []string
		for _, u := range f.UsedBy {
			name := u.Unit
			if name == "" {
				name = u.Command
			}
			if !slices.Contains(units, name) {
				units = append(units, name)
			}
			if !slices.Contains(pkgs, u.Package) {
				pkgs = append(pkgs, u.Package)
			}
		}
		out = append(out, Step{Title: "Restart what loads them",
			Detail:   "After the steps above, restart " + strings.Join(units, ", ") + " (or reboot), so they load " + cn + "'s libraries instead of the old ones. Until then the old copies stay in memory.",
			Packages: pkgs})
	}
	if names := plan(PlanRemove); len(names) > 0 {
		out = append(out, Step{Title: "Remove these: nothing needs them",
			Detail:   "Nothing installed needs them and nothing running loads them. Remove them with apt purge, and check apt's list first: it should remove nothing else.",
			Packages: names})
	}
	if names := plan(PlanReview); len(names) > 0 {
		var why []string
		for _, l := range f.Obsolete {
			if l.Plan != PlanReview {
				continue
			}
			w := l.Name + ": " + l.Reason
			if s := fromSource[l.Name]; s != nil {
				w += " (likely from " + s.File + ": fixing that source may give it a " + cn + " build)"
			}
			why = append(why, w)
		}
		out = append(out, Step{Title: "Decide on these once the rest is done",
			Detail:   "Something still needs or loads them, so they can't simply go. After the steps above and a fresh report, most become a replacement or a removal. " + strings.Join(why, "; ") + ".",
			Packages: names, Waiting: true})
	}
	if names := plan(""); len(names) > 0 {
		out = append(out, Step{Title: "Upgrade the collector to plan these",
			Detail:   "The collector is too old to say what needs them (sudo heimdall-collect upgrade). Until then, remove them only once nothing loads or depends on them.",
			Packages: names, Waiting: true})
	}
	return out
}

func names(ls []Leftover, keep func(Leftover) bool) []string {
	var out []string
	for _, l := range ls {
		if keep == nil || keep(l) {
			out = append(out, l.Name)
		}
	}
	return out
}
