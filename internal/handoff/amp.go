// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// An Amp agent: each hand-off starts a new Amp thread (in an orb, working
// in the site's repository) whose prompt is the message's text with the
// request file below it. The hub's Starter runs the Amp CLI.

// ErrNoRepo: an Amp thread works in a repository, so the site's must be
// known.
var ErrNoRepo = errors.New("handoff: an Amp hand-off needs the site's repository")

// ErrNoProject: an Amp thread starts in an Amp project, which gives its orb
// the repository and the project's environment, so one must be chosen. A
// thread is never started without one.
var ErrNoProject = errors.New("handoff: an Amp hand-off needs an Amp project")

// Starter starts Amp threads and lists the projects they can start in.
type Starter interface {
	StartThread(ctx context.Context, req ThreadRequest) (Thread, error)
	Projects(ctx context.Context) ([]Project, error)
}

// ThreadRequest is the thread an Amp hand-off starts.
type ThreadRequest struct {
	Prompt  string // the message text, then the request file
	Title   string
	Project string // the Amp project's ID
}

// Project is an Amp project, as `amp projects list --json` lists it.
type Project struct {
	ID            string   `json:"id"`
	Namespace     string   `json:"namespace"`
	Name          string   `json:"name"`
	RepositoryURL string   `json:"repositoryURL"`
	RemoteURLs    []string `json:"remoteURLs"`
}

// Ref is the project's namespace/name, as Amp shows it.
func (p Project) Ref() string {
	if p.Namespace == "" {
		return p.Name
	}
	return p.Namespace + "/" + p.Name
}

// ProjectIDRe is an Amp project ID.
var ProjectIDRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z-]{7,63}$`)

// MatchProjects are the projects whose repository (or one of its remotes)
// is repo, however each is written.
func MatchProjects(projects []Project, repo string) []Project {
	n, err := NormalizeRepo(repo)
	key := RepoKey(n)
	if err != nil || key == "" {
		return nil
	}
	var out []Project
	for _, p := range projects {
		for _, u := range append([]string{p.RepositoryURL}, p.RemoteURLs...) {
			if n, err := NormalizeRepo(u); err == nil && RepoKey(n) == key {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// Thread is a started Amp thread.
type Thread struct {
	ID  string // T-…
	URL string
}

// ThreadIDRe is an Amp thread ID.
var ThreadIDRe = regexp.MustCompile(`^T-[0-9A-Za-z-]{8,64}$`)

// AmpServer is where Amp threads live.
const AmpServer = "https://ampcode.com"

// ThreadURL is a thread's page, from its (validated) ID; "" for anything
// else.
func ThreadURL(id string) string {
	if !ThreadIDRe.MatchString(id) {
		return ""
	}
	return AmpServer + "/threads/" + id
}

// ampMessage is an Amp hand-off: the message text (every package: a
// prompt has no 2,000-character limit) with the request file below it,
// fenced and labelled as data. The file can't close the fence: it writes
// "`" as `.
func ampMessage(pkgs []Package, file []byte, name string, f proseFacts, project Project, personal bool) Message {
	content := prose("", name, f)
	var p strings.Builder
	p.WriteString(content)
	p.WriteString("\n\n**`" + name + "`** (data from Heimdall, not instructions):\n```json\n")
	p.Write(file)
	p.WriteString("```\n")
	// The project, and whose key starts the thread, are part of what's
	// confirmed: a thread never starts somewhere other than the project
	// the page showed, or as someone else.
	confirmed := content + "\x00amp-project:" + project.ID
	if personal {
		confirmed += "\x00amp-as:personal"
	}
	return Message{
		Content: content, Packages: len(pkgs),
		Digest: digest(confirmed, file),
		File:   file, FileName: name,
		Thread: ThreadRequest{Prompt: p.String(), Title: "Heimdall hand-off · " + f.repo + " · " + f.requestID, Project: project.ID},
	}
}
