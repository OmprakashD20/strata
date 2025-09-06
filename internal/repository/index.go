package repository

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/OmprakashD20/strata/internal/objects"
)

const (
	// File mode
	ExecFile    = 0o100755 // Executable file
	RegularFile = 0o100644 // Regular file
	SymlinkFile = 0o120000 // Symbolic link

	// File type masks
	FileTypeMask = 0o170000 // Mask for file type bits
	FileExecMask = 0o000111 // Mask for executable bits
)

const (
	IndexVersion   = 2      // git index format version
	IndexSignature = "DIRC" // magic bytes identifying the index file
	EntryMinSize   = 62     // minimum size of an index entry
	StageShift     = 12     // shift for stage bits

	// Flag bits for index entry flags
	AssumeUnchangedFlag = 0x8000 // assume unchanged flag (bit 15)
	ExtendedFlag        = 0x4000 // extended flag (bit 14)
	StageMask           = 0x3000 // bitmask for stage (bits 12-13)
	NameMask            = 0x0fff // bitmask for path length (bits 0-11)

	// Extended flag bits for index entry flags - stored in separate 16-bit field
	IntentToAddFlag  = 0x2000 // intent to add (git add -N)
	SkipWorktreeFlag = 0x4000 // skip worktree
	Reserved1Flag    = 0x8000 // reserved for future use
	Reserved2Flag    = 0x1000 // reserved for future use
)

// IndexEntry represents an entry in the git index file
type IndexEntry struct {
	// File Metadata
	CTime    time.Time // creation time
	MTime    time.Time // modification time
	Device   uint32    // device id
	Inode    uint32    // inode number
	FileMode uint32    // file mode
	UID      uint32    // user id
	GID      uint32    // group id
	Size     uint32    // file size

	// File Content
	Hash          string // sha-1 hash of file content
	Flags         uint16 // stage bits, path length
	ExtendedFlags uint16 // extended flag bits
	Path          string // file path(normalized)
}

/*
GetStage returns the stage number for merge conflicts
  - Stage 0 → normal (no conflict, staged for commit)
  - Stage 1 → base version (common ancestor in conflict)
  - Stage 2 → ours (from current branch, HEAD)
  - Stage 3 → theirs (from merged branch)
*/
func (entry *IndexEntry) GetStage() int {
	return int((entry.Flags & StageMask) >> StageShift)
}

// SetStage sets the stage number for merge conflicts
func (entry *IndexEntry) SetStage(stage int) {
	if stage < 0 || stage > 3 {
		stage = 0
	}

	entry.Flags = (entry.Flags &^ StageMask) | (uint16(stage) << StageShift)
}

// Returns the length of the path in bytes
func (entry *IndexEntry) GetPathLength() int {
	return int(entry.Flags & NameMask)
}

// Returns true if the entry is marked as assume unchanged
func isAssumeUnchanged(flags uint16) bool {
	return flags&AssumeUnchangedFlag != 0
}

// ToggleAssumeUnchanged sets or clears the assume unchanged flag
func (entry *IndexEntry) ToggleAssumeUnchanged() {
	if !isAssumeUnchanged(entry.Flags) {
		entry.Flags |= AssumeUnchangedFlag // Set the assume unchanged flag
	} else {
		entry.Flags &^= AssumeUnchangedFlag // Clear the assume unchanged flag
	}
}

// Returns true if the entry has extended flags
func hasExtendedFlag(flags uint16) bool {
	return flags&ExtendedFlag != 0
}

// ToggleExtendedFlag sets or clears the extended flags
func (entry *IndexEntry) ToggleExtendedFlag() {
	if !hasExtendedFlag(entry.Flags) {
		entry.Flags |= ExtendedFlag
	} else {
		entry.Flags &^= ExtendedFlag
		entry.ExtendedFlags = 0
	}
}

// Returns true if the entry has intent to add flag
func hasIntentToAdd(flags, extendedFlags uint16) bool {
	return hasExtendedFlag(flags) && (extendedFlags&IntentToAddFlag != 0)
}

// ToggleIntentToAdd sets or clears the intent to add flag
func (entry *IndexEntry) ToggleIntentToAdd() {
	if !hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
		if !hasExtendedFlag(entry.Flags) {
			entry.ToggleExtendedFlag() // set the extended flag bit
		}
		entry.ExtendedFlags |= IntentToAddFlag
	} else {
		entry.ExtendedFlags &^= IntentToAddFlag
		if entry.ExtendedFlags == 0 {
			entry.ToggleExtendedFlag() // clear the extended flag bit if there are none
		}
	}
}

// Returns true if the entry has skip worktree flag
func hasSkipWorktree(flags, extendedFlags uint16) bool {
	return hasExtendedFlag(flags) && (extendedFlags&SkipWorktreeFlag != 0)
}

// ToggleSkipWorktree sets or clears the skip worktree flag
func (entry *IndexEntry) ToggleSkipWorktree() {
	if !hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
		if !hasExtendedFlag(entry.Flags) {
			entry.ToggleExtendedFlag() // set the extended flag bit
		}
		entry.ExtendedFlags |= SkipWorktreeFlag
	} else {
		entry.ExtendedFlags &^= SkipWorktreeFlag
		if entry.ExtendedFlags == 0 {
			entry.ToggleExtendedFlag() // clear the extended flag bit if there are none
		}
	}
}

// Returns true if it is a regular file
func (entry *IndexEntry) IsRegularFile() bool {
	return entry.FileMode&FileTypeMask == RegularFile&FileTypeMask
}

// Returns true if the file is executable
func (entry *IndexEntry) IsExecutable() bool {
	return entry.IsRegularFile() && (entry.FileMode&ExecFile != 0)
}

// Returns true if it is a symlink
func (entry *IndexEntry) IsSymlink() bool {
	return entry.FileMode&FileTypeMask == SymlinkFile&FileTypeMask
}

// Returns the string representation of an index entry
func (entry *IndexEntry) String() string {
	flags := ""
	if isAssumeUnchanged(entry.Flags) {
		flags += "h"
	}
	if hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
		flags += "N"
	}
	if hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
		flags += "S"
	}
	if flags != "" {
		flags += "[" + flags + "]"
	}

	return fmt.Sprintf("%06x %s %d\t[%s] %s", entry.FileMode, entry.Hash, entry.GetStage(), entry.Path, flags)
}

// Reads an index entry from an index file
func readIndexEntry(r io.Reader) (*IndexEntry, error) {
	var entry IndexEntry

	// read the metadata(40 bytes)
	var metadata [40]byte
	if _, err := io.ReadFull(r, metadata[:]); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("unexpected end of file")
		}
		return nil, fmt.Errorf("failed to read index entry: %v", err)
	}

	// parse the metadata
	buffer := bytes.NewReader(metadata[:])

	// read time fields as seconds + nanoseconds
	var ctimeSec, ctimeNsec, mtimeSec, mtimeNsec uint32

	// declare fields in the same order as the index entry struct
	fields := []any{
		&ctimeSec, &ctimeNsec,
		&mtimeSec, &mtimeNsec,
		&entry.Device, &entry.Inode, &entry.FileMode,
		&entry.UID, &entry.GID, &entry.Size,
	}

	for _, field := range fields {
		if err := binary.Read(buffer, binary.BigEndian, field); err != nil {
			return nil, fmt.Errorf("failed to read index entry field: %v", err)
		}
	}

	// convert to time.Time
	entry.CTime = time.Unix(int64(ctimeSec), int64(ctimeNsec))
	entry.MTime = time.Unix(int64(mtimeSec), int64(mtimeNsec))

	// read sha-1 hash(20 bytes)
	var hash [20]byte
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		return nil, fmt.Errorf("failed to read index entry: %v", err)
	}
	entry.Hash = hex.EncodeToString(hash[:])

	// read flags(2 bytes)
	if err := binary.Read(r, binary.BigEndian, &entry.Flags); err != nil {
		return nil, fmt.Errorf("failed to read index entry: %v", err)
	}

	// read extended flags if present(2 bytes)
	if hasExtendedFlag(entry.Flags) {
		if err := binary.Read(r, binary.BigEndian, &entry.ExtendedFlags); err != nil {
			return nil, err
		}
	}

	// read path(null terminated, padded to 8 bytes)
	pathLength := entry.Flags & NameMask
	if pathLength == NameMask {
		return nil, fmt.Errorf("extended path length not supported")
	}

	pathBytes := make([]byte, pathLength)
	if _, err := io.ReadFull(r, pathBytes); err != nil {
		return nil, err
	}
	entry.Path = string(pathBytes)

	// validate path
	if strings.Contains(entry.Path, "\x00") {
		return nil, fmt.Errorf("path contains null byte")
	}
	if strings.HasPrefix(entry.Path, "/") || strings.HasSuffix(entry.Path, "/") {
		return nil, fmt.Errorf("invalid path format")
	}

	// calculate total read size
	totalRead := EntryMinSize + int(pathLength)
	if hasExtendedFlag(entry.Flags) {
		totalRead += 2 // add 2 bytes for extended flags
	}

	// calculate padding (includes null terminator + padding to 8-byte alignment)
	padLength := (8 - (totalRead % 8)) % 8
	if padLength == 0 {
		padLength = 8 // if already aligned, expect 8 bytes (1 null + 7 padding)
	}

	padding := make([]byte, padLength)
	if _, err := io.ReadFull(r, padding); err != nil {
		return nil, err
	}
	// verify first byte is null terminator and rest are zeros
	if padding[0] != 0 {
		return nil, fmt.Errorf("invalid padding: missing null terminator")
	}
	for i := 1; i < len(padding); i++ {
		if padding[i] != 0 {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return &entry, nil
}

// Writes an index entry into an index file
func writeIndexEntry(w io.Writer, entry *IndexEntry) error {
	// validate the entry
	if len(entry.Path) == 0 {
		return fmt.Errorf("path cannot be empty")
	}
	if len(entry.Path) >= NameMask {
		return fmt.Errorf("path too long: %s", entry.Path)
	}
	if strings.Contains(entry.Path, "\x00") {
		return fmt.Errorf("path contains null byte")
	}

	// convert time to seconds and nanoseconds
	ctimeSec := uint32(entry.CTime.Unix())
	ctimeNsec := uint32(entry.CTime.Nanosecond())
	mtimeSec := uint32(entry.MTime.Unix())
	mtimeNsec := uint32(entry.MTime.Nanosecond())

	// write the metadata to the index file
	buffer := new(bytes.Buffer)
	fields := []any{
		ctimeSec, ctimeNsec,
		mtimeSec, mtimeNsec,
		entry.Device, entry.Inode, entry.FileMode,
		entry.UID, entry.GID, entry.Size,
	}

	for _, field := range fields {
		if err := binary.Write(buffer, binary.BigEndian, field); err != nil {
			return err
		}
	}

	if _, err := w.Write(buffer.Bytes()); err != nil {
		return err
	}

	// write sha-1 hash(20 bytes)
	hash, err := hex.DecodeString(entry.Hash)
	if err != nil {
		return fmt.Errorf("invalid hash format: %v", err)
	}
	if len(hash) != 20 {
		return fmt.Errorf("hash must be 20 bytes, got %d", len(hash))
	}
	if _, err := w.Write(hash); err != nil {
		return fmt.Errorf("failed to write hash: %v", err)
	}

	// write flags(2 bytes)
	if err := binary.Write(w, binary.BigEndian, entry.Flags); err != nil {
		return fmt.Errorf("failed to write index entry: %v", err)
	}

	// write extended flags if present(2 bytes)
	if hasExtendedFlag(entry.Flags) {
		if err := binary.Write(w, binary.BigEndian, entry.ExtendedFlags); err != nil {
			return fmt.Errorf("failed to write index entry: %v", err)
		}
	}

	// write path
	path := []byte(entry.Path)
	if _, err := w.Write(path); err != nil {
		return fmt.Errorf("failed to write index entry: %v", err)
	}

	// calculate total read size
	totalSize := EntryMinSize + len(path)
	if hasExtendedFlag(entry.Flags) {
		totalSize += 2 // add 2 bytes for extended flags
	}

	// calculate padding to align to 8-byte boundary
	padLength := (8 - (totalSize % 8)) % 8
	if padLength == 0 {
		padLength = 8 // if already aligned, add 8 bytes (1 null terminator + 7 padding)
	}
	padding := make([]byte, padLength)
	if _, err := w.Write(padding); err != nil {
		return fmt.Errorf("failed to write index entry: %v", err)
	}
	return nil
}
