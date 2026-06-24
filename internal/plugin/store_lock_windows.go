//go:build windows

package plugin

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFileExclusive takes an exclusive lock on the whole file via LockFileEx.
func lockFileExclusive(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		^uint32(0), ^uint32(0), // lock the entire file range
		ol,
	)
}

// unlockFile releases the lock taken by lockFileExclusive.
func unlockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		^uint32(0), ^uint32(0),
		ol,
	)
}
