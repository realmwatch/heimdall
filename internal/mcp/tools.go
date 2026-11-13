// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/history"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/search"
	"github.com/realmwatch/heimdall/internal/store"
)

// maxItems bounds every list so a large fleet can't flood the model's context.
const maxItems = 100

type tool struct {
	description string
	schema      map[string]any
	run         func(ctx context.Context, c caller, args map[string]any) (any, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func arg(args map[string]any, k string) string {
	v, _ := args[k].(string)
	return strings.TrimSpace(v)
}

func limit(args map[string]any, def int) int {
	n := def
	if f, ok := args["limit"].(float64); ok {
		n = int(f)
	}
	return max(1, min(n, maxItems))
}

func (s *Server) add(name string, t tool) {
	if s.tools == nil {
		s.tools = map[string]tool{}
	}
	s.tools[name] = t
	s.order = append(s.order, name)
}

func (s *Server) registerTools() {
	orgArg := str("Organization slug (optional when the install has one org)")
	s.add("search", tool{
		description: "Fleet search. Examples: 'openssl < 3.0.13', 'php = 8.1', 'laravel < 11', 'php-fpm = 8.2', " +
			"'composer:laravel/framework < 11.31', 'CVE-2024-6387', 'site:example.com', 'host:web'.",
		schema: obj(map[string]any{"query": str("Search query"), "limit": map[string]any{"type": "integer"}}, "query"),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			q, err := search.Parse(arg(a, "query"))
			if err != nil {
				return nil, fmt.Errorf("%w: %v", errUser, err)
			}
			res, err := search.Run(ctx, s.st, q, c.scope)
			if err != nil {
				return nil, err
			}
			n := limit(a, 50)
			return map[string]any{"matches": first(res.Matches, n), "total": len(res.Matches),
				"truncated": len(res.Matches) > n, "note": res.Note}, nil
		},
	})
	s.add("patch_priorities", tool{
		description: "What to patch first: open findings across visible hosts, ordered known-exploited (KEV), fixable, severity, EPSS.",
		schema:      obj(map[string]any{"org": orgArg, "limit": map[string]any{"type": "integer"}}),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			r, err := report.Build(ctx, s.st, report.Filter{Org: arg(a, "org"), Scope: c.scope}, s.now())
			if err != nil {
				return nil, err
			}
			type item = priorityItem
			var items []item
			for _, h := range r.Hosts {
				for _, f := range h.Findings {
					items = append(items, item{h.Org, h.Name, f})
				}
			}
			sortItems(items, func(x item) report.Finding { return x.Finding })
			n := limit(a, 25)
			return map[string]any{"findings": first(items, n), "total": len(items), "truncated": len(items) > n}, nil
		},
	})
	s.add("host", tool{
		description: "One host: OS and lifecycle, runtimes, finding counts and top findings, sites, containers, last check-in, " +
			"release_leftovers (apt sources and packages an in-place release upgrade left, and what loads them), " +
			"and its machine ID hash. Name it by hostname, or by machine (the hex SHA-256 of \"heimdall-machine:\" and /etc/machine-id).",
		schema: obj(map[string]any{"host": str("Hostname"), "machine": str("Machine ID hash, instead of host"), "org": orgArg}),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			h, err := s.hostArg(ctx, c, a)
			if err != nil {
				return nil, err
			}
			machine, err := s.st.HostMachine(ctx, h.ID)
			if err != nil {
				return nil, err
			}
			r, err := report.Build(ctx, s.st, report.Filter{Org: h.OrgSlug, Scope: c.scope}, s.now())
			if err != nil {
				return nil, err
			}
			for _, rh := range r.Hosts {
				if rh.Name == h.Name {
					truncated := len(rh.Findings) > maxItems
					rh.Findings = first(rh.Findings, maxItems)
					return map[string]any{"host": rh, "machine": machine, "findings_truncated": truncated}, nil
				}
			}
			return map[string]any{"host": h.Name, "org": h.OrgSlug, "machine": machine, "status": "registered, never reported"}, nil
		},
	})
	s.add("finding", tool{
		description: "Findings by id (the id field of host and patch_priorities findings), open or resolved: " +
			"whether each is still open, when it was last seen and resolved, its package (the source package, with the installed binary packages built from it) and versions. " +
			"Use it to check that a fix took effect after the host's next report.",
		schema: obj(map[string]any{"ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"},
			"description": fmt.Sprintf("Finding ids (at most %d)", store.MaxFindingIDs)}}, "ids"),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			ids, err := idsArg(a, "ids")
			if err != nil {
				return nil, err
			}
			list, err := s.st.FindingsByID(ctx, ids)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", errUser, err)
			}
			out := []map[string]any{}
			found := map[int64]bool{}
			for _, f := range list {
				if !c.scope.CanView(f.OrgID) {
					continue // other orgs' findings look missing
				}
				found[f.ID] = true
				m := map[string]any{"id": f.ID, "org": f.Org, "host": f.Host, "status": "open",
					"advisory": f.Advisory, "cves": nonNil(f.CVEs), "severity": f.Severity, "kev": f.KEV,
					"package": f.Package, "binaries": nonNil(f.Binaries), "installed": f.Version, "ecosystem": f.Ecosystem,
					"first_seen": stamp(f.FirstSeen), "last_seen": stamp(f.LastSeen)}
				if f.Fixed != "" {
					m["fixed"] = f.Fixed
				}
				if f.SiteRoot != "" {
					m["site"] = f.SiteRoot
				}
				if !f.ResolvedAt.IsZero() {
					m["status"], m["resolved_at"] = "resolved", stamp(f.ResolvedAt)
				}
				out = append(out, m)
			}
			var missing []int64
			for _, id := range ids {
				if !found[id] {
					missing = append(missing, id)
				}
			}
			return map[string]any{"findings": out, "not_found": nonNil(missing)}, nil
		},
	})
	s.add("sites", tool{
		description: "Web apps (Laravel/PHP) across visible hosts: PHP-FPM and Laravel versions, lifecycle, require.php mismatches, findings.",
		schema:      obj(map[string]any{"org": orgArg}),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			r, err := report.Build(ctx, s.st, report.Filter{Org: arg(a, "org"), Scope: c.scope}, s.now())
			if err != nil {
				return nil, err
			}
			type site struct {
				Org, Host string
				report.Site
			}
			var out []site
			for _, h := range r.Hosts {
				for _, st := range h.Sites {
					out = append(out, site{h.Org, h.Name, st})
				}
			}
			return map[string]any{"sites": first(out, maxItems), "total": len(out), "truncated": len(out) > maxItems}, nil
		},
	})
	s.add("anomalies", tool{
		description: "Open tripwire alerts (unplanned installs, downgrades, unexpected reboots, silent hosts, untrusted collector…).",
		schema:      obj(map[string]any{}),
		run: func(ctx context.Context, c caller, _ map[string]any) (any, error) {
			list, err := s.st.OpenAnomalies(ctx, c.scope)
			if err != nil {
				return nil, err
			}
			type a struct {
				ID                                           int64
				Org, Host, Rule, Severity, Summary, Detected string
			}
			out := make([]a, 0, len(list))
			for _, v := range first(list, maxItems) {
				out = append(out, a{v.ID, v.Host.OrgSlug, v.Host.Name, v.Rule, v.Severity, v.Summary, v.DetectedAt.UTC().Format("2006-01-02T15:04:05Z")})
			}
			return map[string]any{"anomalies": out, "total": len(list), "truncated": len(list) > maxItems}, nil
		},
	})
	s.add("changes", tool{
		description: "What changed on a host between its two most recent check-ins (packages added, removed, upgraded, downgraded).",
		schema:      obj(map[string]any{"host": str("Hostname"), "org": orgArg}, "host"),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			h, err := s.visibleHost(ctx, c, arg(a, "org"), arg(a, "host"))
			if err != nil {
				return nil, err
			}
			from, to, d, err := history.HostDiff(ctx, s.st, h, 0, 0)
			if err != nil {
				return nil, err
			}
			return map[string]any{"from": from, "to": to, "upgraded": first(d.Upgraded, maxItems),
				"downgraded": first(d.Downgraded, maxItems), "added": first(d.Added, maxItems), "removed": first(d.Removed, maxItems)}, nil
		},
	})
	s.add("drift", tool{
		description: "Packages that differ across visible hosts sharing a tag (e.g. 'web').",
		schema:      obj(map[string]any{"tag": str("Host tag")}, "tag"),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			hosts, rows, err := history.Drift(ctx, s.st, strings.ToLower(arg(a, "tag")), c.scope)
			if err != nil {
				return nil, err
			}
			return map[string]any{"hosts": hosts, "packages": first(rows, maxItems), "total": len(rows), "truncated": len(rows) > maxItems}, nil
		},
	})
	s.registerThreatTools() // threats.go
}

// hostArg resolves a tool's host or machine argument to a host the caller
// may see.
func (s *Server) hostArg(ctx context.Context, c caller, a map[string]any) (store.IngestHost, error) {
	m := arg(a, "machine")
	if m == "" || arg(a, "host") != "" {
		return s.visibleHost(ctx, c, arg(a, "org"), arg(a, "host"))
	}
	org, err := s.orgArg(ctx, c, arg(a, "org"))
	if err != nil {
		return store.IngestHost{}, err
	}
	if store.NormalizeMachine(m) == "" {
		return store.IngestHost{}, fmt.Errorf("%w: machine must be a hex SHA-256 machine ID hash", errUser)
	}
	h, err := s.st.HostByMachine(ctx, org, m)
	if err != nil {
		return h, err
	}
	if !c.scope.CanView(h.OrgID) {
		return store.IngestHost{}, store.ErrNotFound
	}
	return h, nil
}

// idsArg reads an array of positive integer ids (JSON numbers).
func idsArg(a map[string]any, k string) ([]int64, error) {
	raw, _ := a[k].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s is required", errUser, k)
	}
	if len(raw) > store.MaxFindingIDs {
		return nil, fmt.Errorf("%w: at most %d %s", errUser, store.MaxFindingIDs, k)
	}
	ids := make([]int64, 0, len(raw))
	for _, v := range raw {
		f, ok := v.(float64)
		if !ok || f < 1 || f != float64(int64(f)) {
			return nil, fmt.Errorf("%w: %s must be positive integers", errUser, k)
		}
		ids = append(ids, int64(f))
	}
	return ids, nil
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// visibleHost resolves a host the caller may see; others look missing.
func (s *Server) visibleHost(ctx context.Context, c caller, org, name string) (store.IngestHost, error) {
	if name == "" {
		return store.IngestHost{}, fmt.Errorf("%w: host is required", errUser)
	}
	org, err := s.orgArg(ctx, c, org)
	if err != nil {
		return store.IngestHost{}, err
	}
	h, err := s.st.HostByName(ctx, org, name)
	if err != nil {
		return h, err
	}
	if !c.scope.CanView(h.OrgID) {
		return store.IngestHost{}, store.ErrNotFound
	}
	return h, nil
}

// orgArg is org, or the caller's only visible org when org is "".
func (s *Server) orgArg(ctx context.Context, c caller, org string) (string, error) {
	if org != "" {
		return org, nil
	}
	visible, err := s.st.VisibleOrgSlugs(ctx, c.scope)
	if err != nil {
		return "", err
	}
	if len(visible) != 1 {
		return "", fmt.Errorf("%w: org is required (you can see %d orgs)", errUser, len(visible))
	}
	for slug := range visible {
		org = slug
	}
	return org, nil
}

func first[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// sortItems orders findings like the report: KEV, fixable, severity, EPSS.
func sortItems[T any](items []T, f func(T) report.Finding) {
	key := func(x report.Finding) (int, int, int, float64) {
		r, ok := sevRank[x.Severity]
		if !ok {
			r = 4
		}
		kev, fix := 1, 1
		if x.KEV {
			kev = 0
		}
		if x.Fixed != "" {
			fix = 0
		}
		return kev, fix, r, -x.EPSS
	}
	slices.SortStableFunc(items, func(a, b T) int {
		a1, a2, a3, a4 := key(f(a))
		b1, b2, b3, b4 := key(f(b))
		return cmp.Or(cmp.Compare(a1, b1), cmp.Compare(a2, b2), cmp.Compare(a3, b3), cmp.Compare(a4, b4))
	})
}

// priorityItem is one patch_priorities finding, with its host.
type priorityItem struct {
	Org  string `json:"org"`
	Host string `json:"host"`
	report.Finding
}
