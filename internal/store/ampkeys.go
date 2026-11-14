// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// UserAmpKey is a user's own Amp API key, sealed with the hub's secrets
// key (internal/secret): the store never sees the key itself.
type UserAmpKey struct {
	Sealed    []byte
	Hint      string // the key's last four characters
	CreatedAt time.Time
	TestedAt  time.Time // zero until "Test" worked
}

// AmpKeyOf is a user's saved Amp key; ok is false when there's none.
func (s *Store) AmpKeyOf(ctx context.Context, userID int64) (k UserAmpKey, ok bool, err error) {
	var created string
	var tested sql.NullString
	err = s.rd.QueryRowContext(ctx, `SELECT sealed, hint, created_at, tested_at FROM user_amp_keys WHERE user_id = ?`, userID).
		Scan(&k.Sealed, &k.Hint, &created, &tested)
	if errors.Is(err, sql.ErrNoRows) {
		return UserAmpKey{}, false, nil
	}
	if err != nil {
		return UserAmpKey{}, false, err
	}
	k.CreatedAt, k.TestedAt = parseTime(created), parseNullTime(tested)
	return k, true, nil
}

// SetAmpKey saves (or replaces) a user's sealed Amp key, audited as
// user.amp_key_set. Neither the key nor its sealed form is audited.
func (s *Store) SetAmpKey(ctx context.Context, actor string, userID int64, sealed []byte, hint string, now time.Time) error {
	if len(sealed) < 29 || len(sealed) > 2048 {
		return &ValidationError{"key", "the sealed key's size is out of range"}
	}
	if len(hint) > 8 {
		return &ValidationError{"hint", "too long"}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var replaced bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM user_amp_keys WHERE user_id = ?)`, userID).Scan(&replaced); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_amp_keys (user_id, sealed, hint, created_at, tested_at) VALUES (?, ?, ?, ?, NULL)
			ON CONFLICT (user_id) DO UPDATE SET sealed = excluded.sealed, hint = excluded.hint,
				created_at = excluded.created_at, tested_at = NULL`,
			userID, sealed, hint, now.UTC().Format(timeLayout)); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "user.amp_key_set", Target: UserRef(userID),
			Detail: map[string]any{"replaced": replaced}})
	})
}

// DeleteAmpKey removes a user's Amp key, audited as user.amp_key_removed.
// It reports whether there was one.
func (s *Store) DeleteAmpKey(ctx context.Context, actor string, userID int64) (bool, error) {
	var removed bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM user_amp_keys WHERE user_id = ?`, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		removed = true
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "user.amp_key_removed", Target: UserRef(userID)})
	})
	return removed, err
}

// AmpKeyTested records that the saved key worked: only when it's still
// the key that was tested (sealed), not one saved since.
func (s *Store) AmpKeyTested(ctx context.Context, userID int64, sealed []byte, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_amp_keys SET tested_at = ? WHERE user_id = ? AND sealed = ?`,
		now.UTC().Format(timeLayout), userID, sealed)
	return err
}
