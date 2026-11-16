// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"encoding/json"
	"strings"
	"testing"
)

func phpReq() PHPRequest {
	return PHPRequest{Version: "v0.5.33", Org: "acme", Host: "web-01", Site: "app.example.com", SitePath: "/var/www/app",
		Repo: "git@github.com:acme/app.git", Stage: PHPCompat, From: "8.1", To: "8.4", Requirement: "^8.1",
		Sites: []PHPSite{{Host: "web-01", Site: "app.example.com", SitePath: "/var/www/app", Branch: "main", PHP: "8.1"},
			{Host: "web-02", SitePath: "/var/www/app", Branch: "bad branch", PHP: "8.x"}},
		RequestID: "0123456789abcdef", RequestedBy: "Jane", Link: "https://heimdall.example.com/hosts/acme/web-01/site?root=%2Fvar%2Fwww%2Fapp",
		AmpProject: Project{ID: "11111111-0000-0000-0000-000000000001"}}
}

func TestBuildPHP(t *testing.T) {
	t.Parallel()
	msg, err := BuildPHP(ampAgent, phpReq())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Make `acme/app` run on PHP 8.4 as well as PHP 8.1", "from the repository's default branch",
		"`config.platform.php` to `8.1`", "`composer why-not php 8.4.0`", "Don't raise the minimum PHP to 8.4", "Finish by giving the pull request's link."} {
		if !strings.Contains(msg.Content, want) {
			t.Errorf("prompt lacks %q:\n%s", want, msg.Content)
		}
	}
	if !strings.HasPrefix(msg.Thread.Prompt, msg.Content+"\n\n") || msg.Thread.Title != "Heimdall PHP 8.4 · acme/app · 0123456789abcdef" ||
		msg.Thread.Project != "11111111-0000-0000-0000-000000000001" {
		t.Errorf("thread %+v", msg.Thread)
	}
	var f map[string]any
	if err := json.Unmarshal(msg.File, &f); err != nil {
		t.Fatal(err)
	}
	sites := f["sites"].([]any)
	second := sites[1].(map[string]any)
	if f["format"] != PHPFileFormat || f["from_php"] != "8.1" || f["require_php"] != "^8.1" || f["base"] != nil ||
		f["suggested_branch"] != "heimdall/php-8.4-compat-01234567" || len(sites) != 2 || second["branch"] != nil || second["php_fpm_version"] != nil {
		t.Errorf("file %s", msg.File)
	}

	// The project and who it runs as are part of the digest.
	r := phpReq()
	r.AmpPersonal = true
	if m, _ := BuildPHP(ampAgent, r); m.Digest == msg.Digest {
		t.Error("running as the user doesn't change the digest")
	}

	// The floor: no from, the base branch named.
	r = phpReq()
	r.Stage, r.Base, r.Requirement = PHPFloor, "dev", "not a constraint;"
	m, err := BuildPHP(ampAgent, r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Content, "Make PHP 8.4 the minimum for `acme/app`") || !strings.Contains(m.Content, "from `dev`") ||
		!strings.Contains(m.Content, "`require.php` is not stated") || strings.Contains(string(m.File), "from_php") {
		t.Errorf("floor:\n%s\n%s", m.Content, m.File)
	}

	for name, mod := range map[string]func(*PHPRequest){
		"not newer":   func(r *PHPRequest) { r.To = "8.1" },
		"bad target":  func(r *PHPRequest) { r.To = "8.4`" },
		"bad stage":   func(r *PHPRequest) { r.Stage = "all" },
		"bad branch":  func(r *PHPRequest) { r.Base = "a b" },
		"no repo":     func(r *PHPRequest) { r.Repo = "" },
		"no project":  func(r *PHPRequest) { r.AmpProject = Project{} },
		"bad path":    func(r *PHPRequest) { r.SitePath = "relative" },
		"bad request": func(r *PHPRequest) { r.RequestID = "x" },
	} {
		r := phpReq()
		mod(&r)
		if _, err := BuildPHP(ampAgent, r); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := BuildPHP(Agent{Name: "pr-bot", UserID: "123456789012345678"}, phpReq()); err == nil {
		t.Error("a Discord agent got a PHP hand-off")
	}
}

func TestComparePHP(t *testing.T) {
	t.Parallel()
	if ComparePHP("8.10", "8.9") <= 0 || ComparePHP("7.4", "8.1") >= 0 || ComparePHP("8.4", "8.4") != 0 {
		t.Error("ComparePHP")
	}
}
