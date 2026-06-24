//go:build !windows

package plugin

import (
	"os"
	"syscall"
)

// lockFileExclusive takes an exclusive advisory lock on the file (flock).
func lockFileExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile releases the advisory lock.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
