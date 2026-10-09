//go:build windows

package core

import "os"

func ownerID() int                   { return -1 }
func directorySync(f *os.File) error { return nil } // Windows sandbox tests do not certify Android fsync/SELinux.
func getMetadata(p string) (Metadata, error) {
	s, e := os.Stat(p)
	if e != nil {
		return Metadata{}, e
	}
	// Windows cannot model group/other POSIX bits. Normalize owner bits for sandbox
	// transaction tests; real permissions and SELinux are exercised on Android.
	mode := uint32(0600)
	if s.IsDir() {
		mode = 0700
	}
	if s.Mode().Perm()&0200 == 0 {
		mode = 0400
	}
	return Metadata{mode, -1, -1, ""}, nil
}
func setMetadata(p string, m Metadata) error { return os.Chmod(p, os.FileMode(m.Mode)) }
func enoughSpace(p string, b uint64) error   { return nil }              // Android implementation is mandatory at runtime.
func pidAlive(p int) bool                    { return p == os.Getpid() } // Only in offline test executable; phone uses kill(0).
