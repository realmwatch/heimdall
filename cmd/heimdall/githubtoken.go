// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// githubCredential is the systemd credential holding the optional GitHub
// token feed sync reads PHP's advisories with. GitHub's API answers
// without one (60 requests an hour per address, plenty for a sync every
// few hours); a token only raises that limit, for hubs that share an
// address with other GitHub API clients.
const githubCredential = "heimdall-github"

// defaultGitHubTokenFile is where the unit's LoadCredential line reads it.
const defaultGitHubTokenFile = "/etc/heimdall/github-token"

// cmdFeedsSetGitHubToken stores the token exactly like `ai set-key`
// stores the AI key.
func cmdFeedsSetGitHubToken(a *app, args []string) error {
	fs := a.flags("feeds set-github-token", "[--file path] [--stdin] [--unit path]")
	path := fs.String("file", defaultGitHubTokenFile, "where to store the token (the unit's LoadCredential source)")
	fromStdin := fs.Bool("stdin", false, "read the token from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var tok string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(a.stdin, 4097))
		if err != nil {
			return err
		}
		tok = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the token")
		}
		if tok, err = in.line("GitHub token, fine-grained, public repositories only, no permissions (input hidden): ", true); err != nil {
			return err
		}
		tok = strings.TrimSpace(tok)
	}
	if tok == "" {
		return errors.New("empty token")
	}
	if len(tok) > 255 || strings.ContainsFunc(tok, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like a GitHub token")
	}
	if err := writePrivate(*path, tok+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the GitHub token in %s (owner-only).\n", *path)
	if *path == defaultGitHubTokenFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, githubCredential, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, githubCredential, *path)
			return nil
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", githubCredential, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintln(a.stderr, "Apply it with: sudo heimdall restart")
	return nil
}

// githubToken reads the optional GitHub token from its systemd credential,
// or from HEIMDALL_GITHUB_TOKEN_FILE; with fallback (CLI as root), from the
// default file. "" with no error when none is set.
func githubToken(fallback bool) (string, error) {
	path, fromSystemd := os.Getenv("HEIMDALL_GITHUB_TOKEN_FILE"), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, githubCredential)); err == nil {
				path, fromSystemd = filepath.Join(dir, githubCredential), true
			}
		}
	}
	if path == "" && keyFallback(fallback) {
		if _, err := os.Stat(defaultGitHubTokenFile); err == nil {
			path = defaultGitHubTokenFile
		}
	}
	if path == "" {
		return "", nil
	}
	perm, b, err := readKeyFile(path)
	if err != nil {
		return "", fmt.Errorf("GitHub token: %w", err)
	}
	if !fromSystemd && perm&0o077 != 0 {
		return "", fmt.Errorf("GitHub token %s is readable by other users; run `chmod 600 %s`", path, path)
	}
	if len(b) > 4096 {
		return "", fmt.Errorf("GitHub token %s is suspiciously large", path)
	}
	return strings.TrimSpace(string(b)), nil
}
