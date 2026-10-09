//go:build linux || android

package core

import (
	"errors"
	"os"
	"syscall"
)

func ownerID() int                   { return os.Geteuid() }
func directorySync(f *os.File) error { return f.Sync() }
func getMetadata(p string) (Metadata, error) {
	s, e := os.Stat(p)
	if e != nil {
		return Metadata{}, e
	}
	x := s.Sys().(*syscall.Stat_t)
	m := Metadata{uint32(s.Mode().Perm()), int(x.Uid), int(x.Gid), ""}
	n, e := syscall.Getxattr(p, "security.selinux", nil)
	if e != nil {
		if errors.Is(e, syscall.ENODATA) || errors.Is(e, syscall.ENOTSUP) {
			return m, nil
		}
		return m, e
	}
	b := make([]byte, n)
	_, e = syscall.Getxattr(p, "security.selinux", b)
	if e != nil {
		return m, e
	}
	m.SELinux = string(b)
	return m, nil
}
func setMetadata(p string, m Metadata) error {
	if e := os.Chown(p, m.UID, m.GID); e != nil {
		return e
	}
	if e := os.Chmod(p, os.FileMode(m.Mode)); e != nil {
		return e
	}
	if m.SELinux != "" {
		if e := syscall.Setxattr(p, "security.selinux", []byte(m.SELinux), 0); e != nil {
			return e
		}
	}
	got, e := getMetadata(p)
	if e != nil {
		return e
	}
	if got.Mode != m.Mode || got.UID != m.UID || got.GID != m.GID || (m.SELinux != "" && got.SELinux != m.SELinux) {
		return fail("E_METADATA", "Ownership, permissions or SELinux verification failed.")
	}
	return nil
}
func enoughSpace(p string, bytes uint64) error {
	var s syscall.Statfs_t
	if e := syscall.Statfs(p, &s); e != nil {
		return e
	}
	if uint64(s.Bavail)*uint64(s.Bsize) < bytes {
		return fail("E_SPACE", "Not enough free space for a complete backup and commit.")
	}
	return nil
}
func pidAlive(p int) bool { e := syscall.Kill(p, 0); return e == nil || e == syscall.EPERM }
