// SPDX-License-Identifier: AGPL-3.0-or-later

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strconv"
)

// A Sealer encrypts secrets the hub keeps in its database for a user
// (their own Amp API key), with the hub's secrets key: a 32-byte key in
// the heimdall-secrets systemd credential, so a copy of the database
// alone doesn't give the secrets away.
//
// A sealed value is a version byte (sealVersion), a random 12-byte nonce,
// and the AES-256-GCM ciphertext and tag. The user's ID and the secret's
// purpose are its additional authenticated data, so a value can't be
// moved to another user, or used as another kind of secret.
type Sealer struct{ aead cipher.AEAD }

// SealKeySize is the secrets key's size in bytes.
const SealKeySize = 32

const sealVersion = 1

// ErrSealed: a sealed value that doesn't open: tampered with, another
// user's, or sealed with another key.
var ErrSealed = errors.New("secret: sealed value can't be opened (tampered, another user's, or another secrets key)")

// NewSealer returns a Sealer for a SealKeySize-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != SealKeySize {
		return nil, errors.New("secret: the secrets key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func sealAAD(purpose string, userID int64) []byte {
	return []byte("heimdall/" + purpose + "/user:" + strconv.FormatInt(userID, 10))
}

// Seal encrypts plaintext for one user and purpose (e.g. "amp-key").
func (s *Sealer) Seal(purpose string, userID int64, plaintext []byte) []byte {
	out := make([]byte, 1+s.aead.NonceSize(), 1+s.aead.NonceSize()+len(plaintext)+s.aead.Overhead())
	out[0] = sealVersion
	rand.Read(out[1:]) // never fails (crypto/rand panics instead)
	return s.aead.Seal(out, out[1:], plaintext, sealAAD(purpose, userID))
}

// Open decrypts a value Seal made for the same user and purpose.
func (s *Sealer) Open(purpose string, userID int64, sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < 1+n+s.aead.Overhead() || sealed[0] != sealVersion {
		return nil, ErrSealed
	}
	b, err := s.aead.Open(nil, sealed[1:1+n], sealed[1+n:], sealAAD(purpose, userID))
	if err != nil {
		return nil, ErrSealed
	}
	return b, nil
}
