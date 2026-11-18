// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// NginxState is what a host's collector read from nginx's configuration
// (migration 0051).
type NginxState struct {
	Servers       int  `json:"servers"`        // http server blocks
	HTTP2         int  `json:"http2"`          // of them, speaking HTTP/2
	HTTP3         int  `json:"http3"`          // listening for QUIC
	ProxyProtocol bool `json:"proxy_protocol"` // a listen takes the PROXY protocol
	Mail          bool `json:"mail"`           // a mail{} block
	Resolver      bool `json:"resolver"`       // a resolver is set
	MP4           bool `json:"mp4"`            // mp4 is on somewhere
	// Restart: "yes" when nginx started before its binary was installed
	// (still running the old code), "no", "stopped", or "unknown".
	Restart string `json:"restart"`
	// RootHTTP2 maps a server block's root to whether it speaks HTTP/2.
	RootHTTP2 map[string]bool `json:"root_http2,omitempty"`
}

// Feature reports whether the nginx part an advisory is about is in use
// (see nginx.Advisory.Feature): known is false for a feature the
// collector doesn't look for.
func (n NginxState) Feature(f string) (on, known bool) {
	switch f {
	case "http2":
		return n.HTTP2 > 0, true
	case "http3":
		return n.HTTP3 > 0, true
	case "proxy_protocol":
		return n.ProxyProtocol, true
	case "mail":
		return n.Mail, true
	case "resolver":
		return n.Resolver, true
	case "mp4":
		return n.MP4, true
	}
	return false, false
}

// SetHostNginx records a host's nginx settings.
func (s *Store) SetHostNginx(ctx context.Context, hostID int64, st NginxState, at time.Time) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO host_nginx (host_id, state, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET state = excluded.state, seen_at = excluded.seen_at`,
		hostID, string(b), at.UTC().Format(timeLayout))
	return err
}

// HostNginx is a host's nginx settings; ok is false when its collector
// never reported them.
func (s *Store) HostNginx(ctx context.Context, hostID int64) (st NginxState, ok bool, err error) {
	var v string
	err = s.rd.QueryRowContext(ctx, `SELECT state FROM host_nginx WHERE host_id = ?`, hostID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	if err := json.Unmarshal([]byte(v), &st); err != nil {
		return st, false, err
	}
	return st, true, nil
}

// ClearHostNginx forgets a host's nginx settings (nginx was removed).
func (s *Store) ClearHostNginx(ctx context.Context, hostID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM host_nginx WHERE host_id = ?`, hostID)
	return err
}

// HostNginxAll is every host's nginx settings, by host ID.
func (s *Store) HostNginxAll(ctx context.Context) (map[int64]NginxState, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, state FROM host_nginx`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]NginxState{}
	for rows.Next() {
		var id int64
		var v string
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		var st NginxState
		if json.Unmarshal([]byte(v), &st) == nil {
			out[id] = st
		}
	}
	return out, rows.Err()
}
