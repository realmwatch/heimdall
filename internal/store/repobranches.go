// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/realmwatch/heimdall/internal/handoff"
)

// RepoBranch is the branch an operator made a repository's default target
// for hand-offs (repo is a handoff.RepoKey), or "" when none was, and its
// pull requests go to the repository's own default branch.
func (s *Store) RepoBranch(ctx context.Context, orgID int64, repo string) (string, error) {
	var b string
	err := s.rd.QueryRowContext(ctx, `SELECT branch FROM repo_branches WHERE org_id = ? AND repo = ?`, orgID, repo).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return b, err
}

// SetRepoBranch makes branch a repository's default target for hand-offs,
// or with branch "" goes back to its own default branch.
func (s *Store) SetRepoBranch(ctx context.Context, actor string, orgID int64, repo, branch string, now time.Time) error {
	if repo == "" || len(repo) > 512 {
		return &ValidationError{"repo", "a repository is required"}
	}
	if branch != "" && !handoff.ValidBranch(branch) {
		return &ValidationError{"branch", "a branch name is letters, digits, \".\", \"_\", \"-\" and \"/\""}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if branch == "" {
			_, err = tx.ExecContext(ctx, `DELETE FROM repo_branches WHERE org_id = ? AND repo = ?`, orgID, repo)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO repo_branches (org_id, repo, branch, updated_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (org_id, repo) DO UPDATE SET branch = excluded.branch, updated_at = excluded.updated_at`,
				orgID, repo, branch, now.UTC().Format(timeLayout))
		}
		if err != nil {
			return fmt.Errorf("repo branch: %w", err)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "handoff.branch", OrgID: orgID, Target: repo,
			Detail: map[string]any{"branch": branch}})
	})
}
