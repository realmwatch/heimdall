// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// The fleet-quiet check: one host going silent is that host's problem
// (CheckFastSilence); most of an org's hosts going silent at once, or every
// host that reports from outside while the hub's own collector still does,
// is the hub's: its public ingest (a reverse proxy, DNS, a firewall) is
// down. It needs no configuration: each host's threshold comes from how
// often it usually reports.
const (
	// FleetCadenceMax: only hosts that usually report at least this often
	// count (an hourly timer does; a daily one doesn't).
	FleetCadenceMax = 2 * time.Hour
	// A host is quiet once it's missed twice its usual gap, and at least
	// FleetQuietFloor.
	FleetQuietFloor = 30 * time.Minute
	// FleetHold: the condition must hold this long before it's shown and
	// sent, and be gone this long before "back" is.
	FleetHold = 10 * time.Minute
	// FleetActiveWithin: hosts that last reported longer ago than this
	// (before the episode, while one is open) were already gone.
	FleetActiveWithin = 48 * time.Hour
	// FleetMinQuiet: at least this many hosts must be quiet.
	FleetMinQuiet = 2
	// fleetCadenceReports: the usual gap is the median of the gaps between
	// a host's last reports.
	fleetCadenceReports = 6
	fleetMaxHosts       = 50
)

// FleetAlerts is what the fleet-quiet check found: episodes to send a
// "public ingest looks down" notice for, and ones that ended.
type FleetAlerts struct {
	Down []store.FleetQuiet
	Back []store.FleetQuiet
}

// fleetObs is one host as the check sees it.
type fleetObs struct {
	name  string
	seen  time.Time
	quiet bool
	where string // reportOrigin
}

// reportOrigin sorts the address a host last reported from: "hub" (the
// hub's own machine), "tailnet", "local" (a private network), or ""
// (outside, through the public ingest, or unknown).
func reportOrigin(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return "hub"
	case ipinfo.Tailnet.Contains(a) || ipinfo.Tailnet6.Contains(a):
		return "tailnet"
	case a.IsPrivate() || a.IsLinkLocalUnicast():
		return "local"
	}
	return ""
}

// CheckFleetQuiet updates each org's episode. An org is quiet when, of its
// hosts that usually report at least every FleetCadenceMax and reported in
// the last FleetActiveWithin, at least FleetMinQuiet have missed twice
// their usual gap and they are a majority; or when at least FleetMinQuiet
// hosts report from outside and all of them are quiet while a host on the
// hub, the tailnet or a private network still reports. Hosts in a
// maintenance window, or with the silence rule suppressed, don't count.
// An episode is confirmed after FleetHold and returned in Down until
// MarkFleetAlerts records it was sent; once the condition has been gone
// for FleetHold it's returned in Back.
func (e *Engine) CheckFleetQuiet(ctx context.Context) (FleetAlerts, error) {
	var out FleetAlerts
	now := e.Now()
	open, err := e.Store.FleetQuietStates(ctx)
	if err != nil {
		return out, err
	}
	states := map[int64]store.FleetQuiet{}
	cutoffs := map[int64]time.Time{}
	since := now.Add(-FleetActiveWithin)
	for _, q := range open {
		states[q.OrgID] = q
		c := q.HeldSince.Add(-FleetActiveWithin)
		if base := now.Add(-FleetActiveWithin); c.After(base) {
			c = base
		}
		cutoffs[q.OrgID] = c
		if c.Before(since) {
			since = c
		}
	}
	hosts, err := e.Store.FleetHosts(ctx, since)
	if err != nil {
		return out, err
	}
	byOrg := map[int64][]fleetObs{}
	slugs := map[int64]string{}
	reporting := map[string]bool{}
	for _, h := range hosts {
		cutoff, ok := cutoffs[h.OrgID]
		if !ok {
			cutoff = now.Add(-FleetActiveWithin)
		}
		if h.LastSeenAt.Before(cutoff) {
			continue
		}
		cadence, ok, err := e.cadence(ctx, h.ID)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		if skip, err := e.silenceExcused(ctx, h.ID, now); err != nil {
			return out, err
		} else if skip {
			continue
		}
		// After a hub restart, hosts get their usual time to report again
		// before they count as quiet: the hub was down, not the ingest. An
		// open episode keeps going, so a restart doesn't end it.
		from := h.LastSeenAt
		if _, isOpen := states[h.OrgID]; !isOpen && e.Started.After(from) {
			from = e.Started
		}
		o := fleetObs{name: h.Name, seen: h.LastSeenAt, where: reportOrigin(h.ReportIP),
			quiet: now.Sub(from) > max(2*cadence, FleetQuietFloor)}
		if !o.quiet && o.where != "" {
			reporting[o.where] = true
		}
		byOrg[h.OrgID] = append(byOrg[h.OrgID], o)
		slugs[h.OrgID] = h.OrgSlug
	}
	still := ""
	for _, w := range []string{"hub", "tailnet", "local"} {
		if reporting[w] {
			still = w
			break
		}
	}

	orgs := make([]int64, 0, len(byOrg)+len(states))
	for id := range byOrg {
		orgs = append(orgs, id)
	}
	for id := range states {
		if _, ok := byOrg[id]; !ok {
			orgs = append(orgs, id)
		}
	}
	slices.Sort(orgs)
	for _, org := range orgs {
		obs := byOrg[org]
		var quiet []fleetObs
		outside, outsideQuiet := 0, 0
		for _, o := range obs {
			if o.quiet {
				quiet = append(quiet, o)
			}
			if o.where == "" {
				outside++
				if o.quiet {
					outsideQuiet++
				}
			}
		}
		majority := len(quiet) >= FleetMinQuiet && 2*len(quiet) > len(obs)
		cutOff := outside >= FleetMinQuiet && outsideQuiet == outside && still != ""
		st, isOpen := states[org]
		if majority || cutOff {
			if !isOpen {
				st = store.FleetQuiet{OrgID: org, OrgSlug: slugs[org], HeldSince: now}
			}
			st.ClearSince = time.Time{}
			st.Quiet, st.Total, st.Still, st.Outside = len(quiet), len(obs), still, cutOff
			st.QuietSince, st.Hosts = medianSeen(quiet), nil
			for _, o := range first(quiet, fleetMaxHosts) {
				st.Hosts = append(st.Hosts, o.name)
			}
			if st.ConfirmedAt.IsZero() && now.Sub(st.HeldSince) >= FleetHold {
				st.ConfirmedAt = now
				e.Log.Warn("public ingest looks down", "org", st.OrgSlug, "quiet", st.Quiet, "of", st.Total, "still", still)
			}
			if err := e.Store.PutFleetQuiet(ctx, st); err != nil {
				return out, err
			}
			if !st.ConfirmedAt.IsZero() && !st.Notified {
				out.Down = append(out.Down, st)
			}
			continue
		}
		if !isOpen {
			continue
		}
		switch {
		case st.ConfirmedAt.IsZero() || !st.Notified:
			// A blip, or nothing ever went out: nothing to say "back" about.
			if err := e.Store.DeleteFleetQuiet(ctx, org); err != nil {
				return out, err
			}
		case st.ClearSince.IsZero():
			st.ClearSince = now
			if err := e.Store.PutFleetQuiet(ctx, st); err != nil {
				return out, err
			}
		case now.Sub(st.ClearSince) >= FleetHold:
			out.Back = append(out.Back, st)
		}
	}
	return out, nil
}

// MarkFleetAlerts records that the notices for a check went out: a Down
// episode isn't sent again, and a Back one is closed.
func (e *Engine) MarkFleetAlerts(ctx context.Context, a FleetAlerts) error {
	for _, q := range a.Down {
		q.Notified = true
		if err := e.Store.PutFleetQuiet(ctx, q); err != nil {
			return err
		}
	}
	for _, q := range a.Back {
		e.Log.Info("ingest is back", "org", q.OrgSlug)
		if err := e.Store.DeleteFleetQuiet(ctx, q.OrgID); err != nil {
			return err
		}
	}
	return nil
}

// cadence is how often a host usually reports: the median gap between its
// last reports. ok is false for a host without enough reports, or one that
// reports less often than FleetCadenceMax.
func (e *Engine) cadence(ctx context.Context, hostID int64) (time.Duration, bool, error) {
	facts, err := e.Store.RecentSnapshotFacts(ctx, hostID, fleetCadenceReports)
	if err != nil || len(facts) < 3 {
		return 0, false, err
	}
	gaps := make([]time.Duration, 0, len(facts)-1)
	for i := 1; i < len(facts); i++ {
		gaps = append(gaps, facts[i-1].ReceivedAt.Sub(facts[i].ReceivedAt))
	}
	slices.Sort(gaps)
	c := gaps[len(gaps)/2]
	return c, c > 0 && c <= FleetCadenceMax, nil
}

// silenceExcused reports whether a host's silence is expected now: it's in
// a maintenance window, or the silence rule is suppressed for it.
func (e *Engine) silenceExcused(ctx context.Context, hostID int64, now time.Time) (bool, error) {
	if muted, err := e.Store.Suppressed(ctx, hostID, "silence", now); err != nil || muted {
		return muted, err
	}
	windows, err := e.Store.WindowsFor(ctx, hostID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(windows, func(w store.Window) bool { return w.Overlaps(now, now) }), nil
}

// medianSeen is when the quiet hosts stopped: the median of their last
// reports, so one host that was already gone doesn't move it.
func medianSeen(quiet []fleetObs) time.Time {
	if len(quiet) == 0 {
		return time.Time{}
	}
	ts := make([]time.Time, 0, len(quiet))
	for _, o := range quiet {
		ts = append(ts, o.seen)
	}
	slices.SortFunc(ts, func(a, b time.Time) int { return a.Compare(b) })
	return ts[(len(ts)-1)/2]
}
