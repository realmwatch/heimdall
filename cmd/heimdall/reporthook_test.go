// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/notify"
)

func TestReportWebhookSetAndTest(t *testing.T) {
	var got *http.Request
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body = make([]byte, r.ContentLength)
		r.Body.Read(body)
	}))
	defer srv.Close()
	oldClient := reportHookHTTPClient
	defer func() { reportHookHTTPClient = oldClient }()
	reportHookHTTPClient = func(string) *http.Client { return srv.Client() }

	dir := t.TempDir()
	unit, cfgPath, secretPath := filepath.Join(dir, "heimdall.service"), filepath.Join(dir, "heimdall.toml"), filepath.Join(dir, "secret")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n"), 0o644)
	os.WriteFile(cfgPath, []byte("database = \"h.db\"\n\n[notify]\nevery = \"0\"\n"), 0o600)
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"-c", cfgPath, "report-webhook", "set", "--file", secretPath, "--unit", unit, "http://changes.example.com/h"}, &out, &errb); err == nil {
		t.Error("plain http accepted")
	}
	if err := run(t.Context(), []string{"-c", cfgPath, "report-webhook", "set", "--file", secretPath, "--unit", unit, srv.URL + "/hooks"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	secret := strings.TrimSpace(out.String())
	if len(secret) != 64 {
		t.Fatalf("secret on stdout: %q", out.String())
	}
	if b, err := os.ReadFile(secretPath); err != nil || string(b) != secret+"\n" {
		t.Errorf("secret file %q %v", b, err)
	}
	if fi, _ := os.Stat(secretPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode %v", fi.Mode())
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "LoadCredential=heimdall-report-webhook:"+secretPath) {
		t.Errorf("unit:\n%s", b)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.ReportWebhook.URL != srv.URL+"/hooks" {
		t.Fatalf("config %+v %v", cfg.ReportWebhook, err)
	}

	t.Setenv("HEIMDALL_REPORT_WEBHOOK_FILE", secretPath)
	errb.Reset()
	if err := run(t.Context(), []string{"-c", cfgPath, "report-webhook", "test"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if got == nil || got.Header.Get(notify.ReportEventHeader) != "test" ||
		got.Header.Get(notify.ReportSignatureHeader) != notify.ReportSignature([]byte(secret), got.Header.Get(notify.ReportTimestampHeader), body) {
		t.Errorf("test event: %v %s", got, body)
	}
}
