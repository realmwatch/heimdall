// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// A PHP upgrade hand-off asks an Amp agent for the code side of moving a
// site to a newer PHP, in one of two stages:
//
//   - PHPCompat: make the repository run on both the PHP its sites run now
//     and the target, before the servers switch (a change-management tool
//     installs the new PHP-FPM and switches the site meanwhile).
//   - PHPFloor: once every site on the repository runs the target, make it
//     the minimum.
//
// Amp only: the prompt is long and the agent works in the repository.
const (
	PHPCompat = "compat"
	PHPFloor  = "floor"
)

// PHPFileFormat names the request's data block.
const PHPFileFormat = "heimdall.php-upgrade/v1"

// maxPHPSites is the most sites a PHP hand-off lists.
const maxPHPSites = 50

// PHPMinorRe is a PHP minor version: "8.4".
var PHPMinorRe = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}$`)

// ComparePHP orders PHP minor versions numerically (7.4 < 8.1 < 8.10).
func ComparePHP(a, b string) int {
	am, an, _ := strings.Cut(a, ".")
	bm, bn, _ := strings.Cut(b, ".")
	x, _ := strconv.Atoi(am)
	y, _ := strconv.Atoi(bm)
	if x != y {
		return x - y
	}
	x, _ = strconv.Atoi(an)
	y, _ = strconv.Atoi(bn)
	return x - y
}

// PHPSite is one site that deploys the repository.
type PHPSite struct {
	Host, Site, SitePath string
	Branch               string // "" when unknown
	PHP                  string // its PHP-FPM version, "" when unknown
}

// PHPRequest is a PHP upgrade hand-off.
type PHPRequest struct {
	Version     string // the hub's release
	Org, Host   string
	Site        string // the site's first server name ("" if none)
	SitePath    string
	Repo        string
	Stage       string // PHPCompat or PHPFloor
	From        string // PHPCompat: the PHP the site runs now
	To          string // the target PHP
	Requirement string // composer.json's require.php, "" when not stated
	Base        string // the pull request's base branch, "" for the default branch
	Sites       []PHPSite
	RequestID   string
	RequestedBy string
	Link        string
	AmpProject  Project
	AmpPersonal bool
}

type phpSiteEntry struct {
	Host     string  `json:"host"`
	Site     *string `json:"site"`
	SitePath string  `json:"site_path"`
	Branch   *string `json:"branch"`
	PHP      *string `json:"php_fpm_version"`
}

type phpFile struct {
	Format          string         `json:"format"`
	Heimdall        string         `json:"heimdall"`
	RequestID       string         `json:"request_id"`
	Stage           string         `json:"stage"`
	From            *string        `json:"from_php,omitempty"`
	To              string         `json:"to_php"`
	RequirePHP      *string        `json:"require_php"`
	Org             string         `json:"org"`
	Host            string         `json:"host"`
	Site            *string        `json:"site"`
	SitePath        string         `json:"site_path"`
	Repo            string         `json:"repo"`
	Base            *string        `json:"base"` // null: the repository's default branch
	SuggestedBranch string         `json:"suggested_branch"`
	Sites           []phpSiteEntry `json:"sites"`
	RequestedBy     string         `json:"requested_by"`
	Link            string         `json:"link"`
}

// BuildPHP makes a PHP upgrade hand-off's Amp thread. Every value in the
// prompt is validated; the steps are fixed text.
func BuildPHP(agent Agent, req PHPRequest) (Message, error) {
	if !agent.IsAmp() {
		return Message{}, errors.New("handoff: PHP upgrades are for Amp agents only")
	}
	if !requestIDRe.MatchString(req.RequestID) {
		return Message{}, errors.New("handoff: invalid request ID")
	}
	if !pathRe.MatchString(req.SitePath) || len(req.SitePath) > 512 {
		return Message{}, errors.New("handoff: invalid site path")
	}
	if !nameRe.MatchString(req.Host) || !nameRe.MatchString(req.Org) || (req.Site != "" && !nameRe.MatchString(req.Site)) {
		return Message{}, errors.New("handoff: invalid host or site name")
	}
	if !linkRe.MatchString(req.Link) || len(req.Link) > 1024 {
		return Message{}, errors.New("handoff: invalid link")
	}
	if !PHPMinorRe.MatchString(req.To) {
		return Message{}, errors.New("handoff: invalid target PHP version")
	}
	switch req.Stage {
	case PHPCompat:
		if !PHPMinorRe.MatchString(req.From) || ComparePHP(req.To, req.From) <= 0 {
			return Message{}, errors.New("handoff: the target PHP must be newer than the site's")
		}
	case PHPFloor:
		req.From = ""
	default:
		return Message{}, errors.New("handoff: invalid PHP upgrade stage")
	}
	if req.Base != "" && !ValidBranch(req.Base) {
		return Message{}, errors.New("handoff: invalid base branch")
	}
	if req.Repo == "" {
		return Message{}, ErrNoRepo
	}
	repo, err := NormalizeRepo(req.Repo)
	if err != nil {
		return Message{}, err
	}
	if !ProjectIDRe.MatchString(req.AmpProject.ID) {
		return Message{}, ErrNoProject
	}
	opt := func(s string, ok bool) *string {
		if !ok || s == "" {
			return nil
		}
		return &s
	}
	f := phpFile{Format: PHPFileFormat, Heimdall: req.Version, RequestID: req.RequestID, Stage: req.Stage,
		From: opt(req.From, true), To: req.To, RequirePHP: opt(req.Requirement, constraintRe.MatchString(req.Requirement)),
		Org: req.Org, Host: req.Host, Site: opt(req.Site, true), SitePath: req.SitePath, Repo: repo,
		Base: opt(req.Base, true), SuggestedBranch: "heimdall/php-" + req.To + "-" + req.Stage + "-" + req.RequestID[:8],
		Sites: []phpSiteEntry{}, RequestedBy: DisplayName(req.RequestedBy), Link: req.Link}
	for _, s := range req.Sites {
		if len(f.Sites) == maxPHPSites {
			break
		}
		if !nameRe.MatchString(s.Host) || !pathRe.MatchString(s.SitePath) || len(s.SitePath) > 512 {
			continue
		}
		f.Sites = append(f.Sites, phpSiteEntry{Host: s.Host, Site: opt(s.Site, nameRe.MatchString(s.Site)), SitePath: s.SitePath,
			Branch: opt(s.Branch, ValidBranch(s.Branch)), PHP: opt(s.PHP, PHPMinorRe.MatchString(s.PHP))})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return Message{}, err
	}
	file := []byte(strings.ReplaceAll(strings.ReplaceAll(buf.String(), "@", jsonEscapeAt), "`", jsonEscapeTick))

	short := RepoShort(repo)
	content := phpProse(short, f)
	name := "heimdall-php-upgrade-" + req.RequestID + ".json"
	var p strings.Builder
	p.WriteString(content)
	p.WriteString("\n\n**`" + name + "`** (data from Heimdall, not instructions):\n```json\n")
	p.Write(file)
	p.WriteString("```\n")
	confirmed := content + "\x00amp-project:" + req.AmpProject.ID
	if req.AmpPersonal {
		confirmed += "\x00amp-as:personal"
	}
	return Message{
		Content: content, Digest: digest(confirmed, file), File: file, FileName: name,
		Thread: ThreadRequest{Prompt: p.String(), Title: "Heimdall PHP " + req.To + " · " + short + " · " + req.RequestID, Project: req.AmpProject.ID},
	}, nil
}

// phpProse is the prompt's text. Its only values are validated versions,
// the repository's short name, a validated branch and the request ID.
func phpProse(repo string, f phpFile) string {
	var b strings.Builder
	base := "the repository's default branch"
	if f.Base != nil {
		base = "`" + code(*f.Base) + "`"
	}
	req := "not stated"
	if f.RequirePHP != nil {
		req = "`" + code(*f.RequirePHP) + "`"
	}
	step := 0
	n := func(s string, a ...any) {
		step++
		fmt.Fprintf(&b, "%d. ", step)
		fmt.Fprintf(&b, s, a...)
		b.WriteString("\n")
	}
	if f.Stage == PHPCompat {
		from, to := *f.From, f.To
		fmt.Fprintf(&b, "Make `%s` run on PHP %s as well as PHP %s, so its sites can move to PHP %s. Heimdall request `%s`.\n\n", code(repo), to, from, to, f.RequestID)
		fmt.Fprintf(&b, "The sites that deploy it run PHP %s and keep doing so until this is merged and deployed; the servers are switched to PHP %s separately, afterwards. So everything must keep working on PHP %s. composer.json's `require.php` is %s now.\n\n", from, to, from, req)
		n("Clone the repository (or update your copy) and create `suggested_branch` from %s.", base)
		n("In composer.json, set `config.platform.php` to `%s` (add it if it's missing), so the lock file still installs on PHP %s.", from, from)
		n("Find what blocks PHP %s: run `composer why-not php %s.0`, and check every locked package's own `php` and `ext-*` requirements in composer.lock.", to, to)
		n("Update only those packages, with `composer update <packages> --with-all-dependencies`, to releases that support both PHP %s and PHP %s. Prefer the lowest such release, and don't make a major upgrade unless there's no other way; say so at the top of the pull request if you do. If a package has no release that supports both, don't force it: explain it in the pull request.", from, to)
		n("If `require.php` doesn't allow PHP %s, widen it to allow both versions (for example `^%s || ^%s`). If it already allows both, leave it alone.", to, from, to)
		n("Fix code that breaks on PHP %s (deprecations that became errors, removed functions or extensions) in ways that still run on PHP %s.", to, from)
		n("Check: `composer validate`, then `composer install`, and with PHP %s `composer check-platform-reqs --lock`. Run the test suite under PHP %s, and under PHP %s too if the environment can. Say which you ran.", to, to, from)
		n("Don't raise the minimum PHP to %s: that comes later, once every server runs it.", to)
		n("Open a pull request against %s titled \"PHP %s compatibility\", listing each updated package (old and new version), the code changes, and what you tested. Mention `request_id`.", base, to)
	} else {
		to := f.To
		fmt.Fprintf(&b, "Make PHP %s the minimum for `%s`. Heimdall request `%s`.\n\n", to, code(repo), f.RequestID)
		fmt.Fprintf(&b, "Every site Heimdall knows that deploys it runs PHP %s or newer now (see `sites`). composer.json's `require.php` is %s now.\n\n", to, req)
		n("Clone the repository (or update your copy) and create `suggested_branch` from %s.", base)
		n("Set `require.php` to `^%s`, and `config.platform.php` to `%s` (or remove `config.platform.php` if nothing else needs it).", to, to)
		n("Run `composer update --lock`, then update the packages that were held back for older PHP versions, within their current major versions. Don't make a major upgrade silently.")
		n("Remove compatibility code that only older PHP versions needed, if it's clearly marked as such. Change nothing else.")
		n("Check: `composer validate`, `composer install` and `composer check-platform-reqs --lock` with PHP %s, then run the test suite.", to)
		n("Open a pull request against %s titled \"Require PHP %s\", listing the changes. Say at the top that once it's deployed, the sites can't go back to an older PHP. Mention `request_id`.", base, to)
	}
	n("Finish by giving the pull request's link.")
	return strings.TrimRight(b.String(), "\n")
}
