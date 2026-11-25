// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package updates

import (
	"errors"
	"os"
)

func openNoFollow(string) (*os.File, error) {
	return nil, errors.New("upgrading from the UI needs Linux")
}

func groupOf(string) int { return -1 }
