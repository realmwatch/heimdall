// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"time"
)

// NodeBin is a Node.js binary on a host: its path, its version ("" when
// unknown) and whether a process runs it.
type NodeBin struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Running bool   `json:"running,omitempty"`
}

// NodeSite is a site's Node: the binary a running process of the site
// uses ("" when none was seen) and the Node its .nvmrc, .node-version or
// package.json engines.node asks for ("" when none).
type NodeSite struct {
	Bin         string `json:"bin,omitempty"`
	Requirement string `json:"requirement,omitempty"`
}

// HostNode is what a host's collector said about Node.js
// (X-Heimdall-Node).
type HostNode struct {
	Bins   []NodeBin           `json:"bins"`
	Sites  map[string]NodeSite `json:"sites"`
	SeenAt time.Time           `json:"-"`
}

// Caps on what's stored per host.
const (
	MaxNodeBins  = 50
	MaxNodeSites = 500
)

// SetHostNode records a host's Node.js state, replacing the last.
func (s *Store) SetHostNode(ctx context.Context, hostID int64, n HostNode, at time.Time) error {
	if n.Bins == nil {
		n.Bins = []NodeBin{}
	}
	if n.Sites == nil {
		n.Sites = map[string]NodeSite{}
	}
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO host_node (host_id, state, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET state = excluded.state, seen_at = excluded.seen_at`,
		hostID, string(b), at.UTC().Format(timeLayout))
	return err
}

// HostNodes is every host's Node.js state, by host ID; hosts whose
// collector never reported it are absent.
func (s *Store) HostNodes(ctx context.Context) (map[int64]HostNode, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, state, seen_at FROM host_node`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostNode{}
	for rows.Next() {
		var id int64
		var state, at string
		if err := rows.Scan(&id, &state, &at); err != nil {
			return nil, err
		}
		var n HostNode
		if err := json.Unmarshal([]byte(state), &n); err != nil {
			continue
		}
		n.SeenAt = parseTime(at)
		out[id] = n
	}
	return out, rows.Err()
}
