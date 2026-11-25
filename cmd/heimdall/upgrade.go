// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/updates"
)

// releaseBase is where release assets are downloaded from.
var releaseBase = "https://github.com/realmwatch/heimdall/releases/download/"

// Seams for tests.
var (
	upgradeHTTP = func() *netx.Client { return netx.New(netx.UpgradeHosts, "heimdall/"+version) }
	latestURL   = updates.LatestURL
	runShell    = func(a *app, script string, args []string) error {
		cmd := exec.CommandContext(a.ctx, "sh", append([]string{script}, args...)...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.stderr, a.stderr
		return cmd.Run()
	}
	isRoot = func() bool { return os.Geteuid() == 0 }
)

// cmdUpgrade upgrades this hub to the latest (or a given) release by
// running that release's install-hub.sh, after checking the Sigstore
// signature on the release's SHA256SUMS (signature.go) and the script
// against it. The installer then verifies the rest, stops the hub,
// migrates, restarts and rolls back on failure.
func cmdUpgrade(a *app, args []string) error {
	fs := a.flags("upgrade", "[--version vX.Y.Z] [--check] [--skip-signature-check] [--request FILE] [-- install-hub.sh flags]")
	want := fs.String("version", "", "release to install (default: the latest)")
	check := fs.Bool("check", false, "only report whether a newer release exists")
	skipSig := fs.Bool("skip-signature-check", false, "don't check the release's Sigstore signature (only its checksums); for when cosign can't run here")
	request := fs.String("request", "", "upgrade to the release the hub asked for in this file (heimdall-upgrade.service runs this)")
	statusDir := fs.String("status", updates.StatusDir, "with --request: where to record how it went")
	if err := fs.Parse(args); err != nil {
		return err
	}
	extra := fs.Args()
	hc := upgradeHTTP()
	if *request != "" {
		return upgradeFromRequest(a, hc, *request, *statusDir)
	}

	tag := *want
	if tag == "" {
		r, err := updates.Latest(a.ctx, hc, latestURL)
		if err != nil {
			return fmt.Errorf("finding the latest release: %w", err)
		}
		tag = r.Version
	} else if !updates.IsTag(tag) {
		return fmt.Errorf("--version must look like v1.2.3, not %q", tag)
	}

	newer := updates.Newer(tag, version)
	switch {
	case *check && newer:
		fmt.Fprintf(a.stdout, "%s is available (running %s). Upgrade with: sudo heimdall upgrade\n", tag, version)
		return nil
	case *check:
		fmt.Fprintf(a.stdout, "Up to date (%s; latest %s).\n", version, tag)
		return nil
	case *want == "" && !newer && updates.IsTag(version):
		fmt.Fprintf(a.stderr, "Already on the latest release (%s).\n", version)
		return nil
	}
	if !isRoot() {
		return errors.New("upgrading replaces /usr/local/bin/heimdall and restarts the service: run it with sudo")
	}
	return installRelease(a, hc, tag, *skipSig, extra)
}

// installRelease verifies tag's install-hub.sh and runs it.
func installRelease(a *app, hc *netx.Client, tag string, skipSig bool, extra []string) error {
	fmt.Fprintf(a.stderr, "Fetching install-hub.sh for %s\n", tag)
	sums, _, err := hc.Get(a.ctx, releaseBase+tag+"/SHA256SUMS", 1<<16, nil)
	if err != nil {
		return err
	}
	script, _, err := hc.Get(a.ctx, releaseBase+tag+"/install-hub.sh", 1<<20, nil)
	if err != nil {
		return err
	}
	if skipSig {
		fmt.Fprintln(a.stderr, "WARNING: not checking the release's signature (--skip-signature-check); only its checksums")
		extra = append([]string{"--skip-signature-check"}, extra...)
	} else {
		bundle, _, err := hc.Get(a.ctx, releaseBase+tag+"/SHA256SUMS.sigstore.json", 1<<20, nil)
		if err != nil {
			return fmt.Errorf("fetching the release's signature: %w", err)
		}
		if err := verifyReleaseSums(a, hc, sums, bundle); err != nil {
			return err
		}
	}
	if err := checkSum(sums, "install-hub.sh", script); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "heimdall-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "install-hub.sh")
	if err := os.WriteFile(path, script, 0o700); err != nil {
		return err
	}
	return runShell(a, path, append([]string{"--version", tag}, extra...))
}

// upgradeFromRequest is heimdall-upgrade.service: the hub (unprivileged)
// wrote the release it wants to path, and this, as root, installs it if
// it's a newer release, recording how it went in dir for the hub to show.
// The release's signature is always checked. See internal/updates/install.go.
func upgradeFromRequest(a *app, hc *netx.Client, path, dir string) error {
	if !isRoot() {
		return errors.New("--request is for heimdall-upgrade.service, which runs as root")
	}
	now := time.Now().UTC()
	status := updates.Status{From: version, Started: now}
	finish := func(result, msg string) error {
		status.Result, status.Message, status.Finished = result, msg, time.Now().UTC()
		if err := updates.WriteStatus(dir, status); err != nil {
			fmt.Fprintf(a.stderr, "recording the upgrade's result: %v\n", err)
		}
		if result == updates.ResultOK {
			return nil
		}
		return errors.New(msg)
	}
	tag, err := updates.ReadRequest(path)
	if err != nil {
		return finish(updates.ResultRefused, err.Error())
	}
	status.Version = tag
	if !updates.Newer(tag, version) {
		// An old request seen again (the hub restarted, say): nothing to do.
		fmt.Fprintf(a.stderr, "%s isn't newer than %s; nothing to do\n", tag, version)
		if s, ok := (&updates.Installer{Dir: dir}).Status(); ok && s.Version == tag {
			return nil // keep what the last run recorded
		}
		return finish(updates.ResultRefused, tag+" isn't newer than "+version)
	}
	status.Result = updates.ResultRunning
	if err := updates.WriteStatus(dir, status); err != nil {
		return err
	}
	logPath := updates.LogPath(dir)
	os.Remove(logPath)
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return finish(updates.ResultFailed, "opening the log: "+err.Error())
	}
	defer log.Close()
	updates.ShareWithHub(dir, logPath)
	fmt.Fprintf(log, "Upgrading from %s to %s, asked for by the hub (%s)\n", version, tag, now.Format(time.RFC3339))
	sub := *a
	sub.stdout, sub.stderr = io.MultiWriter(a.stdout, log), io.MultiWriter(a.stderr, log)
	if err := installRelease(&sub, hc, tag, false, nil); err != nil {
		fmt.Fprintf(log, "FAILED: %v\n", err)
		return finish(updates.ResultFailed, err.Error())
	}
	return finish(updates.ResultOK, "")
}

// checkSum verifies data against name's entry in a SHA256SUMS file.
func checkSum(sums []byte, name string, data []byte) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if f[0] != got {
				return fmt.Errorf("%s doesn't match the release's SHA256SUMS; not running it", name)
			}
			return nil
		}
	}
	return fmt.Errorf("%s isn't listed in the release's SHA256SUMS", name)
}
