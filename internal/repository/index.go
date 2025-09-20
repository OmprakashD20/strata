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
	"strconv"
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

// Index represents the Git staging area
type Index struct {
	entries  map[string]*IndexEntry
	path     string
	version  uint32
	modified bool
}

// SetPath sets the index file path
func (index *Index) SetPath(path string) {
	if path != index.path {
		index.path = path
		index.modified = true
	}
}

// SetVersion sets the index version
func (index *Index) SetVersion(version uint32) {
	if version != index.version {
		index.version = version
		index.modified = true
	}
}

// SetModified explicitly sets the modified flag
func (index *Index) SetModified(modified bool) {
	index.modified = modified
}

// SetEntries replaces the entire entries map
func (index *Index) SetEntries(entries map[string]*IndexEntry) {
	index.entries = entries
	index.modified = true
}

// SetEntry adds or updates a single entry
func (index *Index) SetEntry(path string, entry *IndexEntry) {
	if index.entries == nil {
		index.entries = make(map[string]*IndexEntry)
	}
	index.entries[path] = entry
	index.modified = true
}

// Removes an index entry from the index file
func (index *Index) RemoveEntry(path string) bool {
	path = strings.ReplaceAll(path, "\\", "/")
	if _, exists := index.entries[path]; exists {
		delete(index.entries, path)
		index.modified = true
		return true
	}
	return false
}

// ClearEntries removes all index entries
func (index *Index) ClearEntries() {
	if len(index.entries) > 0 {
		index.entries = make(map[string]*IndexEntry)
		index.modified = true
	}
}

// Returns the path of the index file
func (index *Index) Path() string {
	return index.path
}

// Returns the version of the index file
func (index *Index) Version() uint32 {
	return index.version
}

// Returns whether the index file has been modified
func (index *Index) Modified() bool {
	return index.modified
}

// Returns the entries of the index file
func (index *Index) Entries() map[string]*IndexEntry {
	if index.entries == nil {
		return make(map[string]*IndexEntry)
	}

	// return a copy to prevent external modification
	entries := make(map[string]*IndexEntry, len(index.entries))
	maps.Copy(entries, index.entries)
	return entries
}

// Returns the entry of the index file for the given path
func (index *Index) Entry(path string) (*IndexEntry, bool) {
	path = strings.ReplaceAll(path, "\\", "/")
	entry, exists := index.entries[path]
	if exists {
		// return a copy to prevent external modification
		entryCopy := *entry
		return &entryCopy, true
	}
	return nil, false
}

// NewIndex creates a new index instance
func NewIndex(gitDir string) (*Index, error) {
	if gitDir == "" {
		return nil, fmt.Errorf("git directory not specified")
	}

	path := filepath.Join(gitDir, "index")
	return &Index{
		entries:  make(map[string]*IndexEntry),
		path:     path,
		version:  IndexVersion,
		modified: false,
	}, nil
}

// Loads the index file from disk
func (index *Index) Load() error {
	file, err := os.Open(index.path)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("unable to read the index file '%s': %v", index.path, err)
	}
	defer file.Close()

	// read and verify the index header(12 bits)
	var header [12]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		if err == io.EOF {
			return fmt.Errorf("index file corrupted")
		}

		return fmt.Errorf("unable to read the index file: %v", err)
	}

	// verify index signature
	if string(header[:4]) != IndexSignature {
		return fmt.Errorf("index file corrupted")
	}

	// check index version
	version := binary.BigEndian.Uint32(header[4:8])
	if version != IndexVersion {
		return fmt.Errorf("unsupported index version: %d", version)
	}
	index.SetVersion(version)

	entryCount := binary.BigEndian.Uint32(header[8:12])
	if entryCount > 1000000 {
		return fmt.Errorf("index file corrupted")
	}
	index.SetEntries(make(map[string]*IndexEntry, entryCount))

	hasher := sha1.New()
	hasher.Write(header[:])

	// create a tee reader to hash data as we read the index entries
	reader := io.TeeReader(file, hasher)

	// read index entries
	for i := range entryCount {
		entry, err := readIndexEntry(reader)
		if err != nil {
			return fmt.Errorf("index entry %d corrupted: %v", i, err)
		}

		// validate the entry
		if len(entry.Path) == 0 {
			return fmt.Errorf("index entry %d has empty path", i)
		}

		// check for duplicate entries
		if _, exists := index.Entry(entry.Path); exists {
			return fmt.Errorf("index entry %d: duplicate path '%s'", i, entry.Path)
		}

		index.SetEntry(entry.Path, entry)
	}

	// read the stored checksum
	var storedChecksum [20]byte
	if _, err := io.ReadFull(file, storedChecksum[:]); err != nil {
		return fmt.Errorf("failed to read index checksum: %v", err)
	}

	// compute the expected checksum
	expectedChecksum := hasher.Sum(nil)

	// verify the checksum
	if !bytes.Equal(storedChecksum[:], expectedChecksum) {
		return fmt.Errorf("index file corrupt: checksum mismatch")
	}

	index.SetModified(false)
	return nil
}

// Save writes the index file to disk
func (index *Index) Save() error {
	if !index.Modified() {
		return nil // nothing to save
	}

	// create temporary file
	temp := index.Path() + ".lock"

	// check if lock file already exists
	if _, err := os.Stat(temp); err == nil {
		return fmt.Errorf("unable to create '%s.lock': file exists", index.Path())
	}

	file, err := os.Create(temp)
	if err != nil {
		return fmt.Errorf("failed to create lock file: %v", err)
	}

	// ensure file cleanup on error
	defer func() {
		file.Close()
		if _, err := os.Stat(temp); err == nil {
			os.Remove(temp)
		}
	}()

	hasher := sha1.New()
	writer := io.MultiWriter(file, hasher)

	// write index header(12 bytes)
	header := make([]byte, 12)
	copy(header[:4], []byte(IndexSignature))
	binary.BigEndian.PutUint32(header[4:8], index.Version())
	binary.BigEndian.PutUint32(header[8:12], uint32(len(index.Entries())))

	if _, err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write index header: %v", err)
	}

	// sort entries by path
	entries := index.Entries()
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// write index entries
	for _, path := range paths {
		entry := entries[path]
		if err := writeIndexEntry(writer, entry); err != nil {
			return fmt.Errorf("failed to write index entry: %v", err)
		}
	}

	// write the checksum
	checksum := hasher.Sum(nil)
	if _, err := writer.Write(checksum); err != nil {
		return fmt.Errorf("failed to write checksum: %v", err)
	}

	// ensure file is synced to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("fsync error: %v", err)
	}
	file.Close()

	// rename lock file to index file
	if err := os.Rename(temp, index.Path()); err != nil {
		return fmt.Errorf("unable to move '%s.lock' file: %v", index.Path(), err)
	}

	index.SetModified(false)
	return nil
}

// AddFile adds a file to the index
func (index *Index) AddFile(workingDir, path string) (*objects.Blob, error) {
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	// normalize the file path
	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	if strings.HasPrefix(normalizedPath, "/") {
		return nil, fmt.Errorf("'%s' is outside repository", path)
	}

	fullPath := filepath.Join(workingDir, path)

	// get the file info
	info, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pathspec '%s' did not match any files", path)
		}
		return nil, fmt.Errorf("unable to stat '%s': %v", path, err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("'%s' is a directory", path)
	}

	var content []byte
	var mode uint32

	switch {
	case info.Mode().IsRegular(): // regular file
		content, err = os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read '%s': %v", path, err)
		}

		mode = RegularFile
		if info.Mode()&FileExecMask != 0 {
			mode = ExecFile // executable file
		}

	case info.Mode()&os.ModeSymlink != 0: // symlink
		target, err := os.Readlink(fullPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read symlink '%s': %v", path, err)
		}
		content = []byte(target)
		mode = SymlinkFile

	case info.Mode().IsDir(): // directory
		return nil, fmt.Errorf("'%s' is a directory", path)

	default:
		return nil, fmt.Errorf("'%s' has an unsupported file type", path)
	}

	blob := objects.NewBlob(content)

	// get the system-specific metadata
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("unable to get file system metadata")
	}

	// convert syscall timestamps to time.Time
	ctime := time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec))
	mtime := time.Unix(int64(stat.Mtimespec.Sec), int64(stat.Mtimespec.Nsec))

	// create the index entry with file metadata
	entry := &IndexEntry{
		CTime:    ctime,
		MTime:    mtime,
		Device:   uint32(stat.Dev),
		Inode:    uint32(stat.Ino),
		FileMode: mode,
		UID:      stat.Uid,
		GID:      stat.Gid,
		Size:     uint32(blob.Size()),
		Path:     normalizedPath,
		Hash:     blob.Hash(),
	}

	// set flags (stage 0, path length)
	pathLen := len(normalizedPath)
	if pathLen >= NameMask {
		return nil, fmt.Errorf("path too long: %s", path)
	}
	entry.Flags = uint16(pathLen)

	// preserve existing flags if entry exists
	if existingEntry, exists := index.Entry(normalizedPath); exists {
		if isAssumeUnchanged(existingEntry.Flags) {
			entry.ToggleAssumeUnchanged()
		}
		if hasExtendedFlag(existingEntry.Flags) {
			entry.ExtendedFlags = existingEntry.ExtendedFlags
			entry.ToggleExtendedFlag()
		}
	}

	// add the entry to index
	index.SetEntry(normalizedPath, entry)

	return blob, nil
}

// AddIntentToAdd adds a file to the index with intent to add flag
func (index *Index) AddIntentToAdd(workingDir, path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// normalize the file path
	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	if strings.HasPrefix(normalizedPath, "/") {
		return fmt.Errorf("'%s' is outside repository", path)
	}

	fullPath := filepath.Join(workingDir, path)

	// get the file info
	info, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("pathspec '%s' did not match any files", path)
		}
		return fmt.Errorf("unable to stat '%s': %v", path, err)
	}

	var mode uint32

	switch {
	case info.Mode().IsRegular(): // regular file
		mode = RegularFile
		if info.Mode()&FileExecMask != 0 {
			mode = ExecFile // executable file
		}

	case info.Mode()&os.ModeSymlink != 0: // symlink
		mode = SymlinkFile

	case info.Mode().IsDir(): // directory
		return fmt.Errorf("'%s' is a directory", path)

	default:
		return fmt.Errorf("'%s' has an unsupported file type", path)
	}

	// empty blob
	blob := objects.NewBlob([]byte{})

	// get the system-specific metadata
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unable to get file system metadata")
	}

	// convert syscall timestamps to time.Time
	ctime := time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec))
	mtime := time.Unix(int64(stat.Mtimespec.Sec), int64(stat.Mtimespec.Nsec))

	// create the index entry with file metadata
	entry := &IndexEntry{
		CTime:    ctime,
		MTime:    mtime,
		Device:   uint32(stat.Dev),
		Inode:    uint32(stat.Ino),
		FileMode: mode,
		UID:      stat.Uid,
		GID:      stat.Gid,
		Size:     uint32(blob.Size()),
		Path:     normalizedPath,
		Hash:     blob.Hash(),
	}

	// set flags (stage 0, path length)
	pathLen := len(normalizedPath)
	if pathLen >= NameMask {
		return fmt.Errorf("path too long: %s", path)
	}
	entry.Flags = uint16(pathLen)

	// preserve existing flags if entry exists
	if existingEntry, exists := index.Entry(normalizedPath); exists {
		if isAssumeUnchanged(existingEntry.Flags) {
			entry.ToggleAssumeUnchanged()
		}
		if hasExtendedFlag(existingEntry.Flags) {
			entry.ExtendedFlags = existingEntry.ExtendedFlags
			entry.ToggleExtendedFlag()
		}
	}

	entry.ToggleIntentToAdd() // set intent to add flag
	index.SetEntry(normalizedPath, entry)

	return nil
}

// buildTree builds a tree object from the current index
func (index *Index) buildTree() (*objects.Tree, error) {
	if len(index.entries) == 0 {
		return nil, fmt.Errorf("unable to write initial tree: empty index")
	}

	// build nested directory structure from flat index paths
	// example: "cmd/main.go" becomes nested map: {"cmd": {"main.go": [IndexEntry]}}
	rootDir := make(map[string]any)

	for _, entry := range index.Entries() {
		// skip conflicted entry or intent to add entry
		if entry.GetStage() != 0 || hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
			continue
		}

		// split path into directory parts
		// example: "internal/utils/hash.go" → ["internal", "utils", "hash.go"]
		parts := strings.Split(entry.Path, "/")
		currentDir := rootDir

		// create the directory structure(ignore the file)
		for i, part := range parts[:len(parts)-1] {
			if currentDir[part] == nil {
				currentDir[part] = make(map[string]any)
			}

			var ok bool
			currentDir, ok = currentDir[part].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("path conflict at '%s'", strings.Join(parts[:i+1], "/"))
			}
		}

		// append the file to the directory
		file := parts[len(parts)-1]
		if currentDir[file] != nil {
			return nil, fmt.Errorf("path conflict at '%s'", entry.Path)
		}
		currentDir[file] = entry
	}

	return buildTreeFromDirectory(index, rootDir)
}

// Converts a directory into a tree object
func buildTreeFromDirectory(index *Index, directory map[string]any) (*objects.Tree, error) {
	if len(directory) == 0 {
		return nil, fmt.Errorf("empty directory")
	}

	var entries []objects.TreeEntry

	keys := make([]string, 0, len(directory))
	for key := range directory {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, name := range keys {
		item := directory[name]

		switch v := item.(type) {
		case *IndexEntry: // a file
			var mode string
			if v.IsRegularFile() {
				if v.IsExecutable() {
					mode = strconv.FormatUint(uint64(ExecFile&0o777777), 8)
				} else {
					mode = strconv.FormatUint(uint64(RegularFile&0o777777), 8)
				}
			} else if v.IsSymlink() {
				mode = strconv.FormatUint(uint64(SymlinkFile&0o777777), 8)
			} else {
				return nil, fmt.Errorf("unsupported file mode: %o", v.FileMode)
			}

			entries = append(entries, objects.TreeEntry{
				Mode: mode,
				Name: name,
				Hash: v.Hash,
			})

		case map[string]any: // a subdirectory
			tree, err := buildTreeFromDirectory(index, v)
			if err != nil {
				return nil, fmt.Errorf("failed to create subtree '%s': %v", name, err)
			}

			entries = append(entries, objects.TreeEntry{
				Mode: "40000", // directory mode
				Name: name,
				Hash: tree.Hash(),
			})

		default:
			return nil, fmt.Errorf("invalid directory item type for '%s'", name)
		}
	}

	tree, err := objects.BuildTree(entries)
	if err != nil {
		return nil, fmt.Errorf("failed to build index tree: %v", err)
	}

	// return the SHA-1 hash of the index tree
	return tree, nil
}

// StatusInfo represents the status of a file in the index
type StatusInfo struct {
	Path        string
	IndexStatus rune // 'U'=unmodified, 'M'=modified, 'A'=added, 'D'=deleted, 'R'=renamed, 'C'=copied
	WorkStatus  rune // 'U'=unmodified, 'M'=modified, 'D'=deleted, '?'=untracked, '!'=ignored
}

// IndexManager manages the index of a repository
type IndexManager struct {
	index      *Index // index of the repository
	workingDir string // working directory of the repository
	gitDir     string // git directory of the repository
}

// Returns the working directory of the repository
func (im *IndexManager) WorkingDir() string {
	return im.workingDir
}

// Returns the git directory of the repository
func (im *IndexManager) GitDir() string {
	return im.gitDir
}

// Returns the index of the repository
func (im *IndexManager) Index() *Index {
	return im.index
}

// NewIndexManager creates a new IndexManager instance
func NewIndexManager(workingDir, gitDir string) (*IndexManager, error) {
	if workingDir == "" {
		return nil, fmt.Errorf("working directory not specified")
	}
	if gitDir == "" {
		return nil, fmt.Errorf("git directory not specified")
	}

	// check if working directory exists
	if _, err := os.Stat(workingDir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("working directory does not exist: %s", workingDir)
		}
		return nil, fmt.Errorf("cannot access working directory: %v", err)
	}

	// check if git directory exists
	if _, err := os.Stat(gitDir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("git directory does not exist: %s", gitDir)
		}
		return nil, fmt.Errorf("cannot access git directory: %v", err)
	}

	index, _ := NewIndex(gitDir)

	return &IndexManager{
		index:      index,
		workingDir: workingDir,
		gitDir:     gitDir,
	}, nil
}

// AddFile adds a single file to the index
func (im *IndexManager) AddFile(path string) (*objects.Blob, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	// add the file to the index
	blob, err := im.Index().AddFile(im.WorkingDir(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to add '%s': %v", path, err)
	}

	// save the index to disk
	if err := im.Index().Save(); err != nil {
		return nil, fmt.Errorf("failed to save index: %v", err)
	}

	return blob, nil
}

// AddIntentToAdd adds a file with the intent to add flag
func (im *IndexManager) AddIntentToAdd(path string) error {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return err
	}

	// add the file with intent to add flag
	if err := im.Index().AddIntentToAdd(im.WorkingDir(), path); err != nil {
		return fmt.Errorf("failed to add '%s': %v", path, err)
	}

	// save the index to disk
	return im.Index().Save()
}

// AddFiles add multiple files to the index
func (im *IndexManager) AddFiles(paths []string) ([]*objects.Blob, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	// add the files to the index
	var blobs []*objects.Blob
	for _, path := range paths {
		blob, err := im.Index().AddFile(im.WorkingDir(), path)
		if err != nil {
			return nil, fmt.Errorf("failed to add '%s': %v", path, err)
		}
		blobs = append(blobs, blob)
	}

	// save the index to disk
	if err := im.Index().Save(); err != nil {
		return nil, fmt.Errorf("failed to save index: %v", err)
	}

	return blobs, nil
}

// SetAssumeUnchanged sets or clears the assume unchanged flag for a file in the index
func (im *IndexManager) SetAssumeUnchanged(path string, assume bool) error {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return err
	}

	entry, exists := im.Index().Entry(strings.ReplaceAll(path, "\\", "/"))
	if !exists {
		return fmt.Errorf("pathspec '%s' did not match any staged files", path)
	}

	// toggle the assume unchanged flag if the desired state differs
	if assume != isAssumeUnchanged(entry.Flags) {
		entry.ToggleAssumeUnchanged()
	}

	// mark the index as modified
	im.Index().SetModified(true)

	// save the index to disk
	return im.Index().Save()
}

// SetSkipWorktree sets or clears the skip worktree flag for a file in the index
func (im *IndexManager) SetSkipWorktree(path string, skip bool) error {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return err
	}

	entry, exists := im.Index().Entry(strings.ReplaceAll(path, "\\", "/"))
	if !exists {
		return fmt.Errorf("pathspec '%s' did not match any staged files", path)
	}

	// toggle the skip worktree flag if the desired state differs
	if skip != hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
		entry.ToggleSkipWorktree()
	}

	// mark the index as modified
	im.Index().SetModified(true)

	// save the index to disk
	return im.Index().Save()
}

// Returns all files marked as assume unchanged in the index
func (im *IndexManager) ListAssumeUnchanged() ([]string, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range im.Index().Entries() {
		if isAssumeUnchanged(entry.Flags) {
			files = append(files, entry.Path)
		}
	}

	return files, nil
}

// Returns all files marked as skip worktree in the index
func (im *IndexManager) ListSkipWorktree() ([]string, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range im.Index().Entries() {
		if hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
			files = append(files, entry.Path)
		}
	}

	return files, nil
}

// Returns all files marked as intent to add in the index
func (im *IndexManager) ListIntentToAdd() ([]string, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range im.Index().Entries() {
		if hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
			files = append(files, entry.Path)
		}
	}

	return files, nil
}

// RemoveFile removes a file from the index
func (im *IndexManager) RemoveFile(path string) error {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return err
	}

	// remove the file from the index
	if !im.Index().RemoveEntry(path) {
		return fmt.Errorf("pathspec '%s' did not match any staged files", path)
	}

	// save the index to disk
	return im.Index().Save()
}

// RemoveFiles removes multiple files from the index
func (im *IndexManager) RemoveFiles(paths []string) error {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return err
	}

	// remove each file from the index
	for _, path := range paths {
		if !im.Index().RemoveEntry(path) {
			return fmt.Errorf("pathspec '%s' did not match any staged files", path)
		}
	}

	// save the index to disk
	return im.Index().Save()
}

// Clear removes all files from the index
func (im *IndexManager) Clear() error {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return err
	}

	// clear all index entries
	im.Index().ClearEntries()

	// save the index to disk
	return im.Index().Save()
}

// GetStatus returns the status of all files in the index and working directory
func (im *IndexManager) GetStatus() ([]StatusInfo, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	var status []StatusInfo
	tracked := make(map[string]bool)

	// check staged files against the working directory
	for _, entry := range im.Index().Entries() {
		tracked[entry.Path] = true

		path := filepath.Join(im.WorkingDir(), entry.Path)
		workStatus := 'U' // unmodified by default

		// skip status check for skip worktree files
		if !(hasSkipWorktree(entry.Flags, entry.ExtendedFlags)) {
			info, err := os.Lstat(path)
			if os.IsNotExist(err) {
				workStatus = 'D'
			} else if err != nil {
				workStatus = '?'
			} else {
				// file exists, check if modified
				if isFileModified(entry, info, path) {
					workStatus = 'M'
				}
			}
		}

		indexStatus := 'A' // staged for commit
		if hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
			indexStatus = 'N' // intent to add
		}

		status = append(status, StatusInfo{
			Path:        entry.Path,
			IndexStatus: indexStatus,
			WorkStatus:  workStatus,
		})
	}

	// check for untracked files in the working directory
	err := filepath.Walk(im.workingDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}

		// skip .git directory
		if info.IsDir() && (info.Name() == ".git" || strings.Contains(path, ".git"+string(os.PathSeparator))) {
			return filepath.SkipDir
		}

		// check only files
		if info.IsDir() {
			return nil
		}

		// get relative path
		relPath, err := filepath.Rel(im.workingDir, path)
		if err != nil {
			return nil
		}

		relPath = strings.ReplaceAll(relPath, "\\", "/")

		// add untracked files to status
		if !tracked[relPath] {
			status = append(status, StatusInfo{
				Path:        relPath,
				IndexStatus: 'U', // unmodified in index (not staged)
				WorkStatus:  '?', // untracked
			})
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan working directory: %v", err)
	}

	return status, nil
}

func isFileModified(entry *IndexEntry, info os.FileInfo, path string) bool {
	// if the file is set to assume unchanged, report it as unmodified
	if isAssumeUnchanged(entry.Flags) {
		return false
	}

	// intent to add entries are always considered modified
	if hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
		return true
	}

	if entry.IsSymlink() != (info.Mode()&os.ModeSymlink != 0) {
		return true
	}

	if entry.IsRegularFile() && uint32(info.Size()) != entry.Size {
		return true
	}

	stat, _ := info.Sys().(*syscall.Stat_t)

	// check modification time
	if uint32(stat.Mtimespec.Sec) == uint32(entry.MTime.Unix()) && uint32(stat.Mtimespec.Nsec) == uint32(entry.MTime.Nanosecond()) {
		// check additional metadata
		if uint32(stat.Ino) == entry.Inode && uint32(stat.Dev) == entry.Device && uint32(info.Size()) == entry.Size {
			return false
		}
	}

	return isContentModified(entry, path)
}

func isContentModified(entry *IndexEntry, path string) bool {
	var content []byte
	var err error

	if entry.IsSymlink() {
		target, err := os.Readlink(path)
		if err != nil {
			return true
		}
		content = []byte(target)
	} else {
		content, err = os.ReadFile(path)
		if err != nil {
			return true
		}
	}

	// compare the content hash
	blob := objects.NewBlob(content)
	currentHash, err := hex.DecodeString(blob.Hash())
	if err != nil {
		return true
	}

	indexHash, err := hex.DecodeString(entry.Hash)
	if err != nil {
		return true
	}

	return !bytes.Equal(currentHash, indexHash)
}

// GetStagedFiles returns a list of staged files in the index
func (im *IndexManager) GetStagedFiles() ([]*IndexEntry, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	entries := im.Index().Entries()
	result := make([]*IndexEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry)
	}

	return result, nil
}

// GetStagedFile returns a staged file in the index
func (im *IndexManager) GetStagedFile(path string) (*IndexEntry, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	// get the entry for the normalized path
	entry, exists := im.index.Entry(path)
	if !exists {
		return nil, fmt.Errorf("pathspec '%s' did not match any staged files", path)
	}

	return entry, nil
}

// ListStagedPath returns the path of all staged files in the index
func (im *IndexManager) ListStagedPath() ([]string, error) {
	// load the index from disk
	if err := im.index.Load(); err != nil {
		return nil, err
	}

	var paths []string
	for _, entry := range im.index.Entries() {
		paths = append(paths, entry.Path)
	}
	return paths, nil
}

// BuildTree builds a tree object from the current index
func (im *IndexManager) BuildTree() (*objects.Tree, error) {
	// load the index from disk
	if err := im.index.Load(); err != nil {
		return nil, err
	}

	return im.index.buildTree()
}

// IndexInfo provides metadata about the index
type IndexInfo struct {
	Version           uint32
	EntryCount        int
	TotalSize         int64
	IsModified        bool
	HasChanges        bool
	IndexPath         string
	IndexExists       bool
	AssumeUnchanged   int
	SkipWorktree      int
	IntentToAdd       int
	ConflictedEntries int
}

// GetIndexInfo returns metadata about the index
func (im *IndexManager) GetIndexInfo() (*IndexInfo, error) {
	// load the index from disk
	if err := im.index.Load(); err != nil {
		return nil, err
	}

	var totalSize int64
	var assumeUnchanged, skipWorktree, intentToAdd, conflictedEntries int

	for _, entry := range im.Index().Entries() {
		totalSize += int64(entry.Size)

		if isAssumeUnchanged(entry.Flags) {
			assumeUnchanged++
		}
		if hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
			skipWorktree++
		}
		if hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
			intentToAdd++
		}
		if entry.GetStage() > 0 {
			conflictedEntries++
		}
	}

	_, err := os.Stat(im.Index().Path())
	indexExists := err == nil

	return &IndexInfo{
		Version:           im.index.Version(),
		EntryCount:        len(im.index.Entries()),
		TotalSize:         totalSize,
		IsModified:        im.index.Modified(),
		HasChanges:        len(im.index.Entries()) > 0,
		IndexPath:         im.index.Path(),
		IndexExists:       indexExists,
		AssumeUnchanged:   assumeUnchanged,
		SkipWorktree:      skipWorktree,
		IntentToAdd:       intentToAdd,
		ConflictedEntries: conflictedEntries,
	}, nil
}

// IndexValidation represents validation results
type IndexValidation struct {
	IsValid  bool
	Errors   []string
	Warnings []string
}

// ValidateIndex checks the integrity of the index
func (im *IndexManager) ValidateIndex() (*IndexValidation, error) {
	validation := &IndexValidation{
		IsValid:  true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// check if index file exists
	if _, err := os.Stat(im.Index().Path()); os.IsNotExist(err) {
		validation.Warnings = append(validation.Warnings, "Index file does not exist (empty repository)")
		return validation, nil
	}

	// load the index file
	if err := im.Index().Load(); err != nil {
		validation.Errors = append(validation.Errors, fmt.Sprintf("Failed to load index: %v", err))
		validation.IsValid = false
		return validation, nil
	}

	// validate each entry
	for _, entry := range im.Index().Entries() {
		// check path validity
		if len(entry.Path) == 0 {
			validation.Errors = append(validation.Errors, "Entry with empty path found")
			validation.IsValid = false
			continue
		}

		if strings.Contains(entry.Path, "\x00") {
			validation.Errors = append(validation.Errors, fmt.Sprintf("Path contains null byte: %s", entry.Path))
			validation.IsValid = false
			continue
		}

		// checks for skip-worktree entries
		if hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
			continue
		}

		// check if file exists in working directory
		path := filepath.Join(im.workingDir, entry.Path)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			// check if file is deleted in working directory
			validation.Warnings = append(validation.Warnings,
				fmt.Sprintf("Staged file does not exist in working directory: %s", entry.Path))
			continue
		}
		if err != nil {
			validation.Warnings = append(validation.Warnings,
				fmt.Sprintf("Cannot access staged file: %s (%v)", entry.Path, err))
			continue
		}

		// validate file type consistency
		if entry.IsSymlink() != (info.Mode()&os.ModeSymlink != 0) {
			validation.Warnings = append(validation.Warnings,
				fmt.Sprintf("File type changed: %s", entry.Path))
			continue
		}

		// check if content has changed (ignore assume unchanged files)
		if isFileModified(entry, info, path) {
			if isAssumeUnchanged(entry.Flags) {
				validation.Warnings = append(validation.Warnings,
					fmt.Sprintf("File marked assume-unchanged but actually modified: %s", entry.Path))
			} else {
				validation.Warnings = append(validation.Warnings,
					fmt.Sprintf("File modified since staging: %s", entry.Path))
			}
		}
	}

	return validation, nil
}

// RefreshIndex updates metadata for unchanged files in the index
func (im *IndexManager) RefreshIndex() (int, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return 0, err
	}

	refreshed := 0
	for path, entry := range im.Index().Entries() {
		// skip assume-unchanged and skip-worktree files
		if isAssumeUnchanged(entry.Flags) || hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
			continue
		}

		// check file in working directory
		path := filepath.Join(im.workingDir, path)
		info, err := os.Lstat(path)
		if err != nil {
			continue // skip files that don't exist or can't be accessed
		}

		// only refresh if content hasn't changed
		if !isFileModified(entry, info, path) {
			// get system-specific metadata
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue // skip if metadata unavailable
			}

			// update the index entry metadata
			entry.MTime = time.Unix(int64(stat.Mtimespec.Sec), int64(stat.Mtimespec.Nsec))
			entry.CTime = time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec))
			entry.Device = uint32(stat.Dev)
			entry.Inode = uint32(stat.Ino)
			entry.UID = stat.Uid
			entry.GID = stat.Gid

			// update the size for regular files
			if entry.IsRegularFile() {
				entry.Size = uint32(info.Size())
			}

			refreshed++
		}
	}

	// save the index if any entries were updated
	if refreshed > 0 {
		im.Index().SetModified(true)
		return refreshed, im.index.Save()
	}

	return 0, nil
}

// IndexStats provides detailed statistics about the index
type IndexStats struct {
	TotalEntries    int
	RegularFiles    int
	ExecutableFiles int
	Symlinks        int
	ConflictedFiles int
	AssumeUnchanged int
	SkipWorktree    int
	IntentToAdd     int
	TotalSize       int64
	AverageSize     int64
	OldestFile      time.Time
	NewestFile      time.Time
}

// GetIndexStats returns detailed statistics about the index
func (im *IndexManager) GetIndexStats() (*IndexStats, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	stats := &IndexStats{}
	entries := im.Index().Entries()
	stats.TotalEntries = len(entries)

	if stats.TotalEntries == 0 {
		return stats, nil
	}

	var totalSize int64
	oldestTime := time.Now()
	newestTime := time.Unix(0, 0)

	for _, entry := range entries {
		// count by file type
		if entry.IsRegularFile() {
			if entry.IsExecutable() {
				stats.ExecutableFiles++
			} else {
				stats.RegularFiles++
			}
		} else if entry.IsSymlink() {
			stats.Symlinks++
		}

		// Count special flags
		if entry.GetStage() > 0 {
			stats.ConflictedFiles++
		}
		if isAssumeUnchanged(entry.Flags) {
			stats.AssumeUnchanged++
		}
		if hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
			stats.SkipWorktree++
		}
		if hasIntentToAdd(entry.Flags, entry.ExtendedFlags) {
			stats.IntentToAdd++
		}

		totalSize += int64(entry.Size)

		mTime := time.Unix(int64(entry.MTime.Unix()), int64(entry.MTime.Nanosecond()))
		if mTime.Before(oldestTime) {
			oldestTime = mTime
		}
		if mTime.After(newestTime) {
			newestTime = mTime
		}
	}

	stats.TotalSize = totalSize
	if stats.TotalEntries > 0 {
		stats.AverageSize = totalSize / int64(stats.TotalEntries)
	}
	stats.OldestFile = oldestTime
	stats.NewestFile = newestTime

	return stats, nil
}

// CompactIndex removes entries for files that no longer exist in the working directory
func (im *IndexManager) CompactIndex() ([]string, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	var toRemove []string

	// check for deleted files
	for path, entry := range im.Index().Entries() {
		// skip skip worktree files
		if hasSkipWorktree(entry.Flags, entry.ExtendedFlags) {
			continue
		}

		// check if file exists in working directory
		fullPath := filepath.Join(im.workingDir, path)
		if _, err := os.Lstat(fullPath); os.IsNotExist(err) {
			toRemove = append(toRemove, path)
		}
	}

	if len(toRemove) > 0 {
		for _, path := range toRemove {
			im.Index().RemoveEntry(path)
		}
		// save the updated index
		return toRemove, im.Index().Save()
	}

	return []string{}, nil
}

// GetConflicts returns files with merge conflicts (stage > 0)
func (im *IndexManager) GetConflicts() ([]*IndexEntry, error) {
	// load the index from disk
	if err := im.Index().Load(); err != nil {
		return nil, err
	}

	var conflicts []*IndexEntry
	for _, entry := range im.Index().Entries() {
		if entry.GetStage() > 0 {
			conflicts = append(conflicts, entry)
		}
	}

	return conflicts, nil
}

// ResolveConflict marks a file as resolved by updating it with the current working directory content
func (im *IndexManager) ResolveConflict(path string) error {
	// todo: implement ResolveConflict

	return nil
}
