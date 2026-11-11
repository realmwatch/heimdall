// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"html"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
)

// A host with PHP 8.1 and 8.4 installed and one site on 8.4: once the
// collector says what uses PHP, the host page offers to remove 8.1.
func TestHostPageUnusedPHP(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	host, _ := e.st.HostByName(ctx, "acme", "web-01")
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	pkgs := snap["packages"].([]any)
	for _, n := range []string{"php8.1-cli", "php8.1-common", "php8.4-cli", "php8.4-common", "php8.4-fpm"} {
		v := "8.1.31-1+deb12u1"
		if strings.HasPrefix(n, "php8.4") {
			v = "8.4.5-1+deb12u1"
		}
		pkgs = append(pkgs, map[string]any{"name": n, "version": v, "arch": "amd64", "source_name": n[:6], "source_version": v})
	}
	snap["packages"] = pkgs
	snap["sites"] = []any{map[string]any{"root": "/var/www/app", "document_root": "/var/www/app/public", "server_names": []string{"app.example.com"},
		"web_server": "nginx", "readable": true, "php_fpm_version": "8.4"}}
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("seed: %+v %v", res, err)
	}

	// Before the collector reports PHP use: no suggestion.
	if page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); strings.Contains(page, "php-unused") {
		t.Error("suggests removal without the collector's PHP state")
	}
	if err := e.st.SetHostPHP(ctx, host.ID, "8.1", []string{"8.4"}, testNow); err != nil {
		t.Fatal(err)
	}
	page := html.UnescapeString(e.get("/hosts/acme/web-01", signedIn(e)).Body.String())
	for _, want := range []string{`id="php-unused"`, "PHP 8.1", `href="#php-unused"`, ">not used</a>", ">1 site</span>",
		"sudo apt-get purge -s php8.1-cli php8.1-common",
		"sudo update-alternatives --set php /usr/bin/php8.4\nsudo apt-get purge php8.1-cli php8.1-common",
		`sudo grep -rlsE 'php8\.1([^0-9]|$)'`} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	if strings.Contains(page, "Propose removal") {
		t.Error("Propose removal shown without action_url")
	}
	if strings.Contains(page, "PHP 8.4 <span") {
		t.Error("offers to remove 8.4, which the site uses")
	}
}

func TestHostPagePHPRemoveButton(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	host, _ := e.st.HostByName(ctx, "acme", "web-01")
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	pkgs := snap["packages"].([]any)
	for _, n := range []string{"php8.1-cli", "php8.1-common", "php8.4-cli", "php8.4-common", "php8.4-fpm"} {
		v := "8.1.31-1"
		if strings.HasPrefix(n, "php8.4") {
			v = "8.4.5-1"
		}
		pkgs = append(pkgs, map[string]any{"name": n, "version": v, "arch": "amd64", "source_name": n[:6], "source_version": v})
	}
	snap["packages"] = pkgs
	snap["sites"] = []any{map[string]any{"root": "/var/www/app", "document_root": "/var/www/app/public", "server_names": []string{"app.example.com"},
		"web_server": "nginx", "readable": true, "php_fpm_version": "8.4"}}
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("seed: %+v %v", res, err)
	}
	if err := e.st.SetHostPHP(ctx, host.ID, "8.4", []string{"8.4"}, testNow); err != nil {
		t.Fatal(err)
	}
	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	if !strings.Contains(page, `href="https://changes.example.com/propose?action=php.remove&amp;org=acme&amp;host=web-01&amp;php=8.1"`) {
		t.Error("host page lacks the removal link for 8.1")
	}
	if strings.Contains(page, "php=8.4") {
		t.Error("offers to remove 8.4, which is in use")
	}
	if strings.Contains(page, "Propose removing all") {
		t.Error("offers to remove all with one version to remove")
	}
}

func TestHostPagePHPRemoveAllButton(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	host, _ := e.st.HostByName(ctx, "acme", "web-01")
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	pkgs := snap["packages"].([]any)
	for _, n := range []string{"php8.1-cli", "php8.1-common", "php8.2-cli", "php8.2-common", "php8.4-cli", "php8.4-common", "php8.4-fpm"} {
		v := "8.1.31-1"
		if strings.HasPrefix(n, "php8.2") {
			v = "8.2.28-1"
		}
		if strings.HasPrefix(n, "php8.4") {
			v = "8.4.5-1"
		}
		pkgs = append(pkgs, map[string]any{"name": n, "version": v, "arch": "amd64", "source_name": n[:6], "source_version": v})
	}
	snap["packages"] = pkgs
	snap["sites"] = []any{map[string]any{"root": "/var/www/app", "document_root": "/var/www/app/public", "server_names": []string{"app.example.com"},
		"web_server": "nginx", "readable": true, "php_fpm_version": "8.4"}}
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("seed: %+v %v", res, err)
	}
	if err := e.st.SetHostPHP(ctx, host.ID, "8.4", []string{"8.4"}, testNow); err != nil {
		t.Fatal(err)
	}
	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	if !strings.Contains(page, `href="https://changes.example.com/propose?action=php.remove&amp;org=acme&amp;host=web-01&amp;php=8.1%2C8.2"`) ||
		!strings.Contains(page, ">Propose removing all 2</a>") {
		t.Error("host page lacks the link removing 8.1 and 8.2")
	}
	if !strings.Contains(page, "php=8.1\"") || !strings.Contains(page, "php=8.2\"") {
		t.Error("each version keeps its own link")
	}
}
