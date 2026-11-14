// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestUserAmpKeys(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	uid, err := s.CreateLocalUser(ctx, "test", "alice@example.com", "Alice", false, "$argon2id$x", []byte("0123456789abcdefghij"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.AmpKeyOf(ctx, uid); ok || err != nil {
		t.Fatalf("none saved: %v %v", ok, err)
	}
	sealed := bytes.Repeat([]byte{0xa5}, 64)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if err := s.SetAmpKey(ctx, "user:1", uid, sealed, "abcd", now); err != nil {
		t.Fatal(err)
	}
	k, ok, err := s.AmpKeyOf(ctx, uid)
	if err != nil || !ok || !bytes.Equal(k.Sealed, sealed) || k.Hint != "abcd" || !k.CreatedAt.Equal(now) || !k.TestedAt.IsZero() {
		t.Fatalf("saved: %+v %v %v", k, ok, err)
	}
	// Tested: only the key that was tested.
	if err := s.AmpKeyTested(ctx, uid, []byte("another sealed value, not this one"), now); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := s.AmpKeyOf(ctx, uid); !k.TestedAt.IsZero() {
		t.Error("recorded a test of another key")
	}
	if err := s.AmpKeyTested(ctx, uid, sealed, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := s.AmpKeyOf(ctx, uid); !k.TestedAt.Equal(now.Add(time.Minute)) {
		t.Errorf("tested at %v", k.TestedAt)
	}
	// Replacing it clears the test.
	if err := s.SetAmpKey(ctx, "user:1", uid, bytes.Repeat([]byte{0x5a}, 64), "wxyz", now); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := s.AmpKeyOf(ctx, uid); k.Hint != "wxyz" || !k.TestedAt.IsZero() {
		t.Errorf("replaced: %+v", k)
	}
	if err := s.SetAmpKey(ctx, "user:1", uid, []byte("short"), "x", now); err == nil {
		t.Error("accepted a sealed value too short to be one")
	}

	if removed, err := s.DeleteAmpKey(ctx, "user:1", uid); !removed || err != nil {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if removed, err := s.DeleteAmpKey(ctx, "user:1", uid); removed || err != nil {
		t.Fatalf("remove again: %v %v", removed, err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT action, target, detail FROM audit_log WHERE action LIKE 'user.amp_key%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, target, detail string
		if err := rows.Scan(&action, &target, &detail); err != nil {
			t.Fatal(err)
		}
		got = append(got, action+" "+target+" "+detail)
		if strings.Contains(detail, "abcd") || strings.Contains(detail, "wxyz") || strings.Contains(strings.ToLower(detail), "a5a5") {
			t.Errorf("%s detail carries the key: %s", action, detail)
		}
	}
	ref := UserRef(uid)
	want := []string{"user.amp_key_set " + ref + ` {"replaced":false}`, "user.amp_key_set " + ref + ` {"replaced":true}`, "user.amp_key_removed " + ref + " {}"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
}

// A user's key goes when they're disabled or deleted.
func TestUserAmpKeyGoesWithUser(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	admin, err := s.CreateLocalUser(ctx, "test", "admin@example.com", "", true, "$argon2id$x", []byte("0123456789abcdefghij"))
	if err != nil {
		t.Fatal(err)
	}
	uid, err := s.CreateLocalUser(ctx, "test", "alice@example.com", "", false, "$argon2id$x", []byte("0123456789abcdefghij"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := bytes.Repeat([]byte{1}, 64)
	if err := s.SetAmpKey(ctx, "test", uid, sealed, "abcd", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserDisabled(ctx, "test", "alice@example.com", true); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.AmpKeyOf(ctx, uid); ok {
		t.Error("a disabled user's key stayed")
	}
	if err := s.SetUserDisabled(ctx, "test", "alice@example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAmpKey(ctx, "test", uid, sealed, "abcd", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, fmt.Sprintf("user:%d", admin), uid, SignInMethods{Local: true}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM user_amp_keys`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a deleted user's key stayed: %d %v", n, err)
	}
}
