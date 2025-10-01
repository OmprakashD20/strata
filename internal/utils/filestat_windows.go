//go:build windows

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

// ExtractFileStat extracts file metadata from os.FileInfo on Windows
func ExtractFileStat(info os.FileInfo) (*FileStat, bool) {
	stat, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return nil, false
	}

	// convert syscall timestamps to time.Time
	ctime := time.Unix(0, stat.CreationTime.Nanoseconds())
	mtime := time.Unix(0, stat.LastWriteTime.Nanoseconds())

	// generate pseudo inode
	inode := uint32(0)
	for _, char := range info.Name() {
		inode = inode*31 + uint32(char)
	}

	return &FileStat{
		CTime:  ctime,
		MTime:  mtime,
		Device: 0,
		Inode:  inode,
		UID:    0,
		GID:    0,
	}, true
}
