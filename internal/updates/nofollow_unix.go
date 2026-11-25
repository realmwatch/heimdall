// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package updates

import (
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// groupOf is the group that owns path, or -1.
func groupOf(path string) int {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Gid)
	}
	return -1
}
