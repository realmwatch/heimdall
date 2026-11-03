// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

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
