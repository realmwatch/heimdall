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

// AmpProject is the Amp project an operator picked for an agent's
// hand-offs on a repository (repo is a handoff.RepoKey), or "" when none
// was picked and the project is matched by its repository.
func (s *Store) AmpProject(ctx context.Context, orgID int64, repo, agent string) (string, error) {
	var id string
	err := s.rd.QueryRowContext(ctx, `SELECT project_id FROM amp_projects WHERE org_id = ? AND repo = ? AND agent = ?`,
		orgID, repo, agent).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SetAmpProject picks the Amp project for an agent's hand-offs on a
// repository, or with projectID "" goes back to matching it by repository.
func (s *Store) SetAmpProject(ctx context.Context, actor string, orgID int64, repo, agent, projectID string, now time.Time) error {
	if repo == "" || len(repo) > 512 {
		return &ValidationError{"repo", "a repository is required"}
	}
	if agent == "" || len(agent) > 64 {
		return &ValidationError{"agent", "an agent is required"}
	}
	if projectID != "" && !handoff.ProjectIDRe.MatchString(projectID) {
		return &ValidationError{"project", "not an Amp project ID"}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if projectID == "" {
			_, err = tx.ExecContext(ctx, `DELETE FROM amp_projects WHERE org_id = ? AND repo = ? AND agent = ?`, orgID, repo, agent)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO amp_projects (org_id, repo, agent, project_id, updated_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (org_id, repo, agent) DO UPDATE SET project_id = excluded.project_id, updated_at = excluded.updated_at`,
				orgID, repo, agent, projectID, now.UTC().Format(timeLayout))
		}
		if err != nil {
			return fmt.Errorf("amp project: %w", err)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "handoff.project", OrgID: orgID, Target: repo,
			Detail: map[string]any{"agent": agent, "project": projectID}})
	})
}
