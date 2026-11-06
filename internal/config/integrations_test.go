// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func TestChangeLinkUpdatesURL(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://changes.example.com/updates?org={org}&host={host}", ""},
		{"https://changes.example.com/updates?f={finding}", "change_link.updates_url: unknown placeholder {finding}"},
		{"http://changes.example.com/updates", "change_link.updates_url: must be an https URL"},
	} {
		c := Default()
		c.ChangeLink.UpdatesURL = tc.url
		err := c.Validate()
		if tc.want == "" && err != nil {
			t.Errorf("%s: %v", tc.url, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want %s", tc.url, err, tc.want)
		}
	}
}

func TestChangeLinkAndReportWebhook(t *testing.T) {
	for _, tc := range []struct {
		link, label, hook string
		want              string // "" = valid
	}{
		{"", "", "", ""},
		{"https://changes.example.com/new?org={org}&host={host}&pkg={package}&f={finding}", "Fix", "https://changes.example.com/hooks", ""},
		{"http://127.0.0.1:8000/new?f={finding}", "", "", ""},
		{"https://changes.example.com/new?f={findings}", "", "", "unknown placeholder {findings}"},
		{"http://changes.example.com/new", "", "", "must be an https URL"},
		{"https://user:pw@changes.example.com/new", "", "", "must be an https URL"},
		{"javascript:alert(1)//{org}", "", "", "must be an https URL"},
		{"", strings.Repeat("x", 25), "", "change_link.label"},
		{"", "", "http://changes.example.com/hooks", "report_webhook.url"},
	} {
		c := Default()
		c.ChangeLink, c.ReportWebhook = ChangeLink{URL: tc.link, Label: tc.label}, ReportWebhook{URL: tc.hook}
		err := c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%+v: %v", tc, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%+v: got %v, want %q", tc, err, tc.want)
		}
	}
	if (ChangeLink{}).LinkLabel() != "Fix" {
		t.Error("default label")
	}
}
