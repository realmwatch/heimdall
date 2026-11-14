// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/realmwatch/heimdall/internal/secret"
)

// The hub's secrets key seals what it keeps in its database for a user
// (their own Amp API key): 32 random bytes in /etc/heimdall/secrets-key,
// root-only, that install-hub.sh makes on install and upgrade and passes
// as the systemd credential heimdall-secrets. Without it, personal Amp
// keys are off and everything else works.
const (
	secretsCredential = "heimdall-secrets"
	secretsKeyFile    = "/etc/heimdall/secrets-key"
)

// errNoSecretsKey: the credential isn't loaded.
var errNoSecretsKey = errors.New("no secrets key")

// secretsKey reads the secrets key: $HEIMDALL_SECRETS_FILE, else the
// credential. The file holds the 32 bytes as they are, or as 64 hex
// digits.
func secretsKey() ([]byte, error) {
	path := os.Getenv("HEIMDALL_SECRETS_FILE")
	if path == "" {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return nil, errNoSecretsKey
		}
		path = filepath.Join(dir, secretsCredential)
	}
	_, b, err := readKeyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoSecretsKey
	}
	if err != nil {
		return nil, err
	}
	if len(b) == secret.SealKeySize {
		return b, nil
	}
	if h := strings.TrimSpace(string(b)); len(h) == 2*secret.SealKeySize {
		if k, err := hex.DecodeString(h); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%s: a secrets key is %d random bytes (or %d hex digits), not %d bytes", path, secret.SealKeySize, 2*secret.SealKeySize, len(b))
}

// hubSealer is the hub's Sealer, or nil (logged) without a usable key.
func hubSealer(log *slog.Logger) *secret.Sealer {
	k, err := secretsKey()
	if errors.Is(err, errNoSecretsKey) {
		log.Info("no secrets key: personal Amp keys are off (upgrading the hub with install-hub.sh adds it)",
			"credential", secretsCredential, "file", secretsKeyFile)
		return nil
	}
	if err == nil {
		var s *secret.Sealer
		if s, err = secret.NewSealer(k); err == nil {
			return s
		}
	}
	log.Error("the secrets key can't be used: personal Amp keys are off", "err", err)
	return nil
}
