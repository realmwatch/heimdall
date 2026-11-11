// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/handoff"
)

// fakeAmp writes a stand-in for the Amp CLI that records its arguments,
// environment and stdin in dir, then prints out and exits with code.
func fakeAmp(t *testing.T, dir, out string, code int) string {
	t.Helper()
	path := filepath.Join(dir, "amp-cli")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + dir + "/args\nenv > " + dir + "/env\ncat > " + dir + "/stdin\n" +
		"printf '%s\\n' '" + out + "'\nexit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAmpStarter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/heimdall.service")
	t.Setenv("HEIMDALL_SECRET", "nope")
	s := &ampStarter{path: fakeAmp(t, dir, "Started https://ampcode.com/threads/T-12345678-aaaa-bbbb-cccc-000000000000", 0),
		key: "sgamp_test_key", home: filepath.Join(dir, "home", "amp")}
	th, err := s.StartThread(t.Context(), handoff.ThreadRequest{Prompt: "**Heimdall hand-off**\n```json\n{}\n```\n",
		Title: "Heimdall hand-off · acme/app · 0123456789abcdef", Project: "https://github.com/acme/app"})
	if err != nil || th.ID != "T-12345678-aaaa-bbbb-cccc-000000000000" || th.URL != "https://ampcode.com/threads/"+th.ID {
		t.Fatalf("thread %+v %v", th, err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if want := "--execute\n--orb-execute\n--no-archive-after-execute\n--title\nHeimdall hand-off · acme/app · 0123456789abcdef\n--project\nhttps://github.com/acme/app\n"; string(args) != want {
		t.Errorf("args:\n%s", args)
	}
	if stdin, _ := os.ReadFile(filepath.Join(dir, "stdin")); string(stdin) != "**Heimdall hand-off**\n```json\n{}\n```\n" {
		t.Errorf("stdin %q", stdin)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	for _, want := range []string{"AMP_API_KEY=sgamp_test_key\n", "HOME=" + s.home + "\n", "AMP_SKIP_UPDATE_CHECK=1\n", "BUN_JSC_useJIT=0\n"} {
		if !bytes.Contains(env, []byte(want)) {
			t.Errorf("env lacks %q", want)
		}
	}
	// None of the hub's own environment (its credentials directory above all).
	if bytes.Contains(env, []byte("CREDENTIALS_DIRECTORY")) || bytes.Contains(env, []byte("HEIMDALL_SECRET")) {
		t.Errorf("the hub's environment leaked:\n%s", env)
	}
	if fi, err := os.Stat(s.home); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("home %v %v", fi, err)
	}
}

func TestAmpStarterFails(t *testing.T) {
	dir := t.TempDir()
	// A failure says why, with the key masked.
	s := &ampStarter{path: fakeAmp(t, dir, "error: invalid key sgamp_test_key", 1), key: "sgamp_test_key", home: filepath.Join(dir, "amp")}
	_, err := s.StartThread(t.Context(), handoff.ThreadRequest{Prompt: "x", Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "invalid key [key]") || strings.Contains(err.Error(), "sgamp_test_key") {
		t.Errorf("err = %v", err)
	}
	// No URL in the output is a failure too.
	s.path = fakeAmp(t, dir, "done", 0)
	if _, err := s.StartThread(t.Context(), handoff.ThreadRequest{Prompt: "x", Title: "t"}); err == nil || !strings.Contains(err.Error(), "no thread URL") {
		t.Errorf("err = %v", err)
	}
	// A thread that started counts even if the CLI then failed.
	s.path = fakeAmp(t, dir, "https://ampcode.com/threads/T-12345678-aaaa-bbbb-cccc-000000000001 then lost the connection", 1)
	if th, err := s.StartThread(t.Context(), handoff.ThreadRequest{Prompt: "x", Title: "t"}); err != nil || th.ID != "T-12345678-aaaa-bbbb-cccc-000000000001" {
		t.Errorf("%+v %v", th, err)
	}
}

func TestHandoffAgentsAmp(t *testing.T) {
	dir := t.TempDir()
	amp := fakeAmp(t, dir, "", 0)
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("sgamp_test_key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Database = filepath.Join(dir, "heimdall.db")
	cfg.Agents = []config.Agent{{Name: "amp", Kind: "amp", AmpPath: amp}, {Name: "amp-2", Kind: "amp", AmpPath: amp}, {Name: "amp-3", Kind: "amp", AmpPath: "/nonexistent/amp"}}
	t.Setenv("HEIMDALL_AGENT_AMP_FILE", key)
	t.Setenv("HEIMDALL_AGENT_AMP_3_FILE", key)
	t.Setenv("STATE_DIRECTORY", "")
	var logs bytes.Buffer
	agents := handoffAgents(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if len(agents) != 1 || agents[0].Name != "amp" || !agents[0].IsAmp() {
		t.Fatalf("agents %+v", agents)
	}
	if s := agents[0].Starter.(*ampStarter); s.key != "sgamp_test_key" || s.home != filepath.Join(dir, "amp") {
		t.Errorf("starter %+v", s)
	}
	// amp-2 has no key and amp-3 no CLI: both left out and logged.
	if l := logs.String(); !strings.Contains(l, "agent=amp-2") || !strings.Contains(l, "agent set-key amp-2") || !strings.Contains(l, "isn't installed at /nonexistent/amp") {
		t.Errorf("log:\n%s", l)
	}
}
