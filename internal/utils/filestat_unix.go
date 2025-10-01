//go:build unix

package utils

import (
	"os"
	"syscall"
	"time"
)

// FileStat represents file metadata
type FileStat struct {
	CTime  time.Time
	MTime  time.Time
	Device uint32
	Inode  uint32
	UID    uint32
	GID    uint32
}

// ExtractFileStat extracts file metadata from os.FileInfo
func ExtractFileStat(info os.FileInfo) (*FileStat, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, false
	}

	// convert syscall timestamps to time.Time
	ctime := time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec))
	mtime := time.Unix(int64(stat.Mtimespec.Sec), int64(stat.Mtimespec.Nsec))

	return &FileStat{
		CTime:  ctime,
		MTime:  mtime,
		Device: uint32(stat.Dev),
		Inode:  uint32(stat.Ino),
		UID:    stat.Uid,
		GID:    stat.Gid,
	}, true
}
