// SPDX-License-Identifier: AGPL-3.0-or-later

package secret

import (
	"bytes"
	"errors"
	"testing"
)

func testSealer(t *testing.T, b byte) *Sealer {
	t.Helper()
	s, err := NewSealer(bytes.Repeat([]byte{b}, SealKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSeal(t *testing.T) {
	t.Parallel()
	s := testSealer(t, 1)
	plain := []byte("sgamp_test_0000000000000000000000")
	a, b := s.Seal("amp-key", 7, plain), s.Seal("amp-key", 7, plain)
	if bytes.Equal(a, b) {
		t.Error("two seals of one value match: the nonce isn't random")
	}
	if bytes.Contains(a, plain) || a[0] != sealVersion {
		t.Errorf("sealed value %x", a)
	}
	got, err := s.Open("amp-key", 7, a)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %q %v", got, err)
	}

	tampered := bytes.Clone(a)
	tampered[len(tampered)-1] ^= 1
	version := bytes.Clone(a)
	version[0] = 2
	for name, open := range map[string]func() ([]byte, error){
		"tampered":      func() ([]byte, error) { return s.Open("amp-key", 7, tampered) },
		"version":       func() ([]byte, error) { return s.Open("amp-key", 7, version) },
		"short":         func() ([]byte, error) { return s.Open("amp-key", 7, a[:20]) },
		"empty":         func() ([]byte, error) { return s.Open("amp-key", 7, nil) },
		"another user":  func() ([]byte, error) { return s.Open("amp-key", 8, a) },
		"other purpose": func() ([]byte, error) { return s.Open("other", 7, a) },
		"another key":   func() ([]byte, error) { return testSealer(t, 2).Open("amp-key", 7, a) },
	} {
		if b, err := open(); !errors.Is(err, ErrSealed) || b != nil {
			t.Errorf("%s: opened %q, %v", name, b, err)
		}
	}
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Error("accepted a 16-byte key")
	}
}
