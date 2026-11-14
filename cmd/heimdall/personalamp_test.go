// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/handoff"
)

const testUserKey = "sgamp_test_00000000000000000000user"

// A personal key runs the agent's CLI with the user's key, in the user's
// own home, and with a project list of its own.
func TestPersonalAmp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", filepath.Join(dir, "state"))
	svc := &ampStarter{path: fakeAmp(t, dir, `[{"id":"0d0c0b0a-1234-4abc-8def-000000000001","name":"app","namespace":"acme","repositoryURL":"https://github.com/acme/app"}]`, 0),
		key: "sgamp_test_service", home: filepath.Join(dir, "state", "amp")}
	agent := handoff.Agent{Name: "amp", Starter: svc}
	p := newPersonalAmp(config.Config{Database: filepath.Join(dir, "heimdall.db")})

	st := p.Starter(agent, 42, testUserKey)
	ps, err := st.Projects(t.Context())
	if err != nil || len(ps) != 1 {
		t.Fatalf("projects %+v %v", ps, err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	home := filepath.Join(dir, "state", "amp-users", "42")
	for _, want := range []string{"AMP_API_KEY=" + testUserKey + "\n", "HOME=" + home + "\n"} {
		if !bytes.Contains(env, []byte(want)) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	if bytes.Contains(env, []byte("sgamp_test_service")) {
		t.Error("the service account's key reached a personal run")
	}
	if fi, err := os.Stat(home); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("home %v %v", fi, err)
	}

	// The list is cached per user and key: the same user and key share it;
	// another user, or a new key, doesn't.
	if a, b := p.Starter(agent, 42, testUserKey).(*ampStarter), st.(*ampStarter); a.shared != b.shared {
		t.Error("the same user and key don't share a project list")
	}
	if a := p.Starter(agent, 43, testUserKey).(*ampStarter); a.shared == st.(*ampStarter).shared {
		t.Error("two users share a project list")
	}
	if a := p.Starter(agent, 42, testUserKey+"x").(*ampStarter); a.shared == st.(*ampStarter).shared {
		t.Error("a new key reuses the old key's project list")
	}
	if svc.cache() == st.(*ampStarter).cache() {
		t.Error("a user shares the service account's project list")
	}
	// Bounded: the least recently used goes.
	for i := range int64(personalAmpLists + 5) {
		p.Starter(agent, 100+i, testUserKey)
	}
	if len(p.lists) != personalAmpLists {
		t.Errorf("%d cached lists", len(p.lists))
	}
	// The key is never kept, only its hash.
	for k := range p.lists {
		if strings.Contains(k, testUserKey) {
			t.Fatal("the cache keeps the key")
		}
	}

	// Not an Amp CLI agent: nothing runs.
	if _, err := p.Starter(handoff.Agent{Name: "bot"}, 42, testUserKey).Projects(t.Context()); err == nil {
		t.Error("a personal starter for a non-Amp agent")
	}
}

func TestPersonalAmpCheck(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", dir)
	agent := handoff.Agent{Name: "amp", Starter: &ampStarter{path: fakeAmp(t, dir, "error: invalid key "+testUserKey, 1)}}
	p := newPersonalAmp(config.Config{})
	err := p.Check(t.Context(), agent, 42, testUserKey)
	if err == nil || strings.Contains(err.Error(), testUserKey) || !strings.Contains(err.Error(), "invalid key [key]") {
		t.Errorf("failed check: %v", err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if string(args) != "threads\nlist\n--limit\n1\n" {
		t.Errorf("args %q", args)
	}
	agent.Starter = &ampStarter{path: fakeAmp(t, dir, "T-1 a thread", 0)}
	if err := p.Check(t.Context(), agent, 42, testUserKey); err != nil {
		t.Errorf("good check: %v", err)
	}
}

func TestSecretsKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HEIMDALL_SECRETS_FILE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := secretsKey(); !errors.Is(err, errNoSecretsKey) {
		t.Errorf("none: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if hubSealer(log) != nil {
		t.Error("a sealer without a key")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, err := secretsKey(); !errors.Is(err, errNoSecretsKey) {
		t.Errorf("credential not loaded: %v", err)
	}
	raw := bytes.Repeat([]byte{0x0a}, 32) // newlines: kept as they are, not trimmed
	if err := os.WriteFile(filepath.Join(dir, secretsCredential), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := secretsKey(); err != nil || !bytes.Equal(k, raw) {
		t.Errorf("raw: %x %v", k, err)
	}
	if hubSealer(log) == nil {
		t.Error("no sealer with a key")
	}
	hexFile := filepath.Join(dir, "hex")
	os.WriteFile(hexFile, []byte(hex.EncodeToString(bytes.Repeat([]byte{7}, 32))+"\n"), 0o600)
	t.Setenv("HEIMDALL_SECRETS_FILE", hexFile)
	if k, err := secretsKey(); err != nil || !bytes.Equal(k, bytes.Repeat([]byte{7}, 32)) {
		t.Errorf("hex: %x %v", k, err)
	}
	os.WriteFile(hexFile, []byte("too short"), 0o600)
	if _, err := secretsKey(); err == nil || errors.Is(err, errNoSecretsKey) {
		t.Errorf("bad key: %v", err)
	}
}
