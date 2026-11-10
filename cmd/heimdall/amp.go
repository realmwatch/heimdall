// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/handoff"
)

// An Amp agent ([[agents]] kind = "amp") starts each hand-off as a new
// Amp thread in an orb, by running the Amp CLI with a service account's
// API key. The key is a systemd credential, heimdall-agent-<name>, that
// `heimdall agent set-key <name>` stores; it reaches the CLI only through
// its environment, never its arguments.

// agentCredential is an Amp agent's credential name and default key file.
func agentCredential(name string) (cred, file string) {
	return "heimdall-agent-" + name, filepath.Join(notifySecretDir, "agent-"+name)
}

// ampThreadRe finds the new thread's URL in the CLI's output.
var ampThreadRe = regexp.MustCompile(`https://ampcode\.com/threads/(T-[0-9A-Za-z-]{8,64})`)

// ampOutputMax caps what's kept of the CLI's output.
const ampOutputMax = 64 << 10

// ampStarter runs the Amp CLI. home is its own directory (HOME and the
// XDG directories) under the hub's state directory, so it never sees the
// hub's files or environment.
type ampStarter struct {
	path, key, home string
}

func (s *ampStarter) env() []string {
	return []string{
		"HOME=" + s.home,
		"XDG_CONFIG_HOME=" + filepath.Join(s.home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(s.home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(s.home, ".local", "share"),
		"XDG_STATE_HOME=" + filepath.Join(s.home, ".local", "state"),
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8", "TERM=dumb", "NO_COLOR=1",
		"AMP_API_KEY=" + s.key,
		// Updates are the operator's: the CLI never replaces itself.
		"AMP_SKIP_UPDATE_CHECK=1",
		// The CLI is a Bun binary. The hub's unit sets
		// MemoryDenyWriteExecute, which forbids the memory a JIT writes
		// code into, so JavaScriptCore runs interpreted.
		"BUN_JSC_useJIT=0", "BUN_JSC_useRegExpJIT=0",
	}
}

// run runs the CLI with args and stdin, returning its combined output
// (capped, with the key masked).
func (s *ampStarter) run(ctx context.Context, stdin string, args ...string) (string, error) {
	if err := os.MkdirAll(s.home, 0o700); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, s.path, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = s.home, s.env(), strings.NewReader(stdin)
	var out cappedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	text := out.String()
	if s.key != "" {
		text = strings.ReplaceAll(text, s.key, "[key]")
	}
	return text, err
}

// StartThread starts the hand-off's thread in an orb, with the prompt on
// stdin, and returns it. The CLI prints the thread's URL and exits while
// the agent works.
func (s *ampStarter) StartThread(ctx context.Context, req handoff.ThreadRequest) (handoff.Thread, error) {
	args := []string{"--execute", "--orb-execute", "--no-archive-after-execute", "--title", req.Title}
	if req.Project != "" {
		args = append(args, "--project", req.Project)
	}
	text, err := s.run(ctx, req.Prompt, args...)
	// A thread that was started counts even if the CLI then failed:
	// sending again would start a second one.
	if m := ampThreadRe.FindStringSubmatch(text); m != nil {
		return handoff.Thread{ID: m[1], URL: handoff.ThreadURL(m[1])}, nil
	}
	if err == nil {
		err = errors.New("no thread URL in its output")
	}
	return handoff.Thread{}, fmt.Errorf("amp: %w: %s", err, tail(text, 600))
}

// tail is the end of s on one line, for a log.
func tail(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

// cappedBuffer keeps the first ampOutputMax bytes written to it.
type cappedBuffer struct{ b []byte }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := ampOutputMax - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return string(c.b) }

// ampHome is the Amp CLI's home: "amp" in the hub's state directory
// (systemd's STATE_DIRECTORY, else the database's directory).
func ampHome(cfg config.Config) string {
	dir, _, _ := strings.Cut(os.Getenv("STATE_DIRECTORY"), ":")
	if dir == "" {
		dir = filepath.Dir(cfg.Database)
	}
	return filepath.Join(dir, "amp")
}

// ampAgent builds an Amp agent's starter, or says why it can't.
func ampAgent(cfg config.Config, a config.Agent, fallback bool) (*ampStarter, error) {
	cred, file := agentCredential(a.Name)
	if !fallback {
		file = ""
	}
	key, _, err := credentialFile(cred, file)
	if err != nil {
		return nil, fmt.Errorf("its Amp API key can't be read: %w (store it with `sudo heimdall agent set-key %s`)", err, a.Name)
	}
	if fi, err := os.Stat(a.Amp()); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("the Amp CLI isn't installed at %s (see docs/deployment.md)", a.Amp())
	}
	return &ampStarter{path: a.Amp(), key: key, home: ampHome(cfg)}, nil
}

// cmdAgentSetKey stores an Amp agent's API key like `ai set-key` stores
// the AI key, and adds its LoadCredential line to the unit.
func cmdAgentSetKey(a *app, args []string) error {
	fs := a.flags("agent set-key", "[--stdin] [--unit path] <name>")
	fromStdin := fs.Bool("stdin", false, "read the key from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	rest, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	name := rest[0]
	if !config.ValidAgentName(name) {
		return errors.New("an agent's name is 1-32 lowercase letters, digits or '-', as in [[agents]] name")
	}
	var key string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(a.stdin, 4097))
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the key")
		}
		if key, err = in.line("Amp API key for "+name+" (input hidden): ", true); err != nil {
			return err
		}
		key = strings.TrimSpace(key)
	}
	if key == "" {
		return errors.New("empty key")
	}
	if len(key) > 4096 || strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like an API key (copy the service account's key from Amp's workspace settings)")
	}
	if !strings.HasPrefix(key, "sgamp_") {
		fmt.Fprintln(a.stderr, "Note: Amp access tokens usually start with sgamp_; check you copied the whole key.")
	}
	cred, path := agentCredential(name)
	if err := writePrivate(path, key+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored %s's Amp API key in %s (owner-only).\n", name, path)
	switch changed, err := enableCredential(*unitFile, cred, path); {
	case err != nil:
		fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, cred, path)
		return nil
	case changed:
		fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", cred, *unitFile)
		if *unitFile == hubUnitFile {
			if err := systemctl(a, "daemon-reload"); err != nil {
				fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
			}
		}
	}
	fmt.Fprintf(a.stderr, "Check it with `sudo heimdall agent test %s`, then apply with: sudo heimdall restart\n", name)
	return nil
}

// cmdAgentTest checks an Amp agent without starting a thread: the CLI
// runs, and the key lists the account's latest thread.
func cmdAgentTest(a *app, args []string) error {
	rest, err := parse(a.flags("agent test", "<name>"), args, 1)
	if err != nil {
		return err
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return err
	}
	var agent config.Agent
	for _, ag := range cfg.Agents {
		if ag.Name == rest[0] {
			agent = ag
		}
	}
	if agent.Name == "" || !agent.IsAmp() {
		return fmt.Errorf("no [[agents]] named %q with kind = \"amp\" in the config", rest[0])
	}
	s, err := ampAgent(cfg, agent, keyFallback(isRoot()))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, time.Minute)
	defer cancel()
	fmt.Fprintf(a.stderr, "Running %s threads list --limit 1 (key from credential %s)\n", s.path, "heimdall-agent-"+agent.Name)
	text, err := s.run(ctx, "", "threads", "list", "--limit", "1")
	if err != nil {
		return fmt.Errorf("test failed: %w: %s", err, tail(text, 600))
	}
	fmt.Fprintln(a.stdout, "OK: the Amp CLI ran and the key works.")
	return nil
}
