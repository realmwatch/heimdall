// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/realmwatch/heimdall/internal/feeds/nginx"
	"github.com/realmwatch/heimdall/internal/store"
)

// nginxExposure adds what the collector read from nginx's configuration:
// the host's nginx state, whether each nginx.org finding's feature is in
// use, and each site's HTTP/2. features caches the advisories' features
// across hosts.
func nginxExposure(ctx context.Context, st *store.Store, hostID int64, host *Host, features *map[string]string) error {
	state, ok, err := st.HostNginx(ctx, hostID)
	if err != nil || !ok {
		return err
	}
	host.Nginx = &state
	for i := range host.Findings {
		f := &host.Findings[i]
		if !strings.HasPrefix(f.Advisory, nginx.IDPrefix) {
			continue
		}
		if *features == nil {
			if *features, err = upstreamFeatures(ctx, st); err != nil {
				return err
			}
		}
		f.Feature = (*features)[f.Advisory]
		if on, known := state.Feature(f.Feature); known {
			f.FeatureOn = &on
		}
	}
	for i := range host.Sites {
		s := &host.Sites[i]
		if s.WebServer != "nginx" {
			continue
		}
		if on, ok := state.RootHTTP2[s.DocumentRoot]; ok {
			s.HTTP2 = &on
		}
	}
	return nil
}

// upstreamFeatures maps each stored nginx.org advisory to its feature.
func upstreamFeatures(ctx context.Context, st *store.Store) (map[string]string, error) {
	recs, err := st.UpstreamAdvisories(ctx, nginx.IDPrefix)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(recs))
	for _, r := range recs {
		var rec struct {
			DatabaseSpecific struct {
				Feature string `json:"feature"`
			} `json:"database_specific"`
		}
		if json.Unmarshal(r.Raw, &rec) == nil {
			out[r.ID] = rec.DatabaseSpecific.Feature
		}
	}
	return out, nil
}

// featureNames are how the host page names each nginx feature.
var featureNames = map[string]string{
	"http2": "HTTP/2", "http3": "HTTP/3", "mail": "mail proxy", "resolver": "resolver",
	"proxy_protocol": "PROXY protocol", "mp4": "mp4",
}

// ExposureLabel says whether the host's nginx uses the part of nginx the
// finding is about ("HTTP/2 on", "HTTP/2 off"), or "" when unknown.
func (f Finding) ExposureLabel() string {
	name := featureNames[f.Feature]
	if f.FeatureOn == nil || name == "" {
		return ""
	}
	if *f.FeatureOn {
		return name + " on"
	}
	return name + " off"
}

// Exposed: the host's nginx uses the part the finding is about.
func (f Finding) Exposed() bool { return f.FeatureOn != nil && *f.FeatureOn }

// NginxHTTP2Findings are the host's open nginx.org findings about HTTP/2.
func (h Host) NginxHTTP2Findings() []Finding {
	var out []Finding
	for _, f := range h.Findings {
		if f.Feature == "http2" && strings.HasPrefix(f.Advisory, nginx.IDPrefix) {
			out = append(out, f)
		}
	}
	return out
}

// HasNginxFindings: the host has open nginx.org findings.
func (h Host) HasNginxFindings() bool {
	for _, f := range h.Findings {
		if strings.HasPrefix(f.Advisory, nginx.IDPrefix) {
			return true
		}
	}
	return false
}

// NginxAlsoInUse names the parts of nginx some advisories are about that
// the host's configuration uses, besides HTTP/2 and HTTP/3.
func (h Host) NginxAlsoInUse() []string {
	if h.Nginx == nil {
		return nil
	}
	var out []string
	for _, f := range []string{"proxy_protocol", "mail", "resolver", "mp4"} {
		if on, _ := h.Nginx.Feature(f); on {
			out = append(out, featureNames[f])
		}
	}
	return out
}

// HTTP2Label: "on" or "off" for the site's HTTP/2, "" when unknown.
func (s Site) HTTP2Label() string {
	switch {
	case s.HTTP2 == nil:
		return ""
	case *s.HTTP2:
		return "on"
	}
	return "off"
}
