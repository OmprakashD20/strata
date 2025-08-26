package objects

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// TreeEntry represents a single entry in a Tree object
type TreeEntry struct {
	Mode string // file mode: "100644" (file), "100755" (executable), "40000" (directory)
	Name string // filename or directory name
	Hash string // sha-1 hash of the referenced object (blob or tree)
}

// Tree represents a directory structure in Git
type Tree struct {
	*BaseObject
	entries []TreeEntry
	hash    string
}

// BuildTree constructs a Tree from a slice of Tree entries
func BuildTree(entries []TreeEntry) (*Tree, error) {
	// validate the tree entries
	for _, entry := range entries {
		if err := validateEntry(entry); err != nil {
			return nil, fmt.Errorf("invalid tree entry %s: %v", entry.Name, err)
		}
	}

	tree := &Tree{
		BaseObject: &BaseObject{
			objectType: TreeType,
		},
		entries: entries,
	}

	// serialize entries to object content
	tree.updateContent()
	tree.hash = tree.BaseObject.Hash()

	return tree, nil
}

// ParseTree reconstructs a Tree from its raw binary encoding
func ParseTree(content []byte) (*Tree, error) {
	entries, err := deserializeEntries(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tree: %w", err)
	}
	tree := &Tree{
		BaseObject: &BaseObject{
			objectType:    TreeType,
			objectContent: bytes.Clone(content),
		},
		entries: entries,
	}

	tree.hash = tree.BaseObject.Hash()

	return tree, nil
}

// MakeEntry adds or updates an entry in the tree
func (t *Tree) MakeEntry(mode, name, hash string) error {
	entry := TreeEntry{Mode: mode, Name: name, Hash: hash}

	// validate the entry
	if err := validateEntry(entry); err != nil {
		return err
	}

	// replace if exists
	for i, e := range t.entries {
		if e.Name == name {
			t.entries[i] = entry
			t.updateContent()
			return nil
		}
	}

	// else, append
	t.entries = append(t.entries, entry)
	t.updateContent()

	return nil
}

// Returns the slice of entries in the tree
func (t *Tree) Entries() []TreeEntry {
	if t == nil {
		return nil
	}

	// return a copy to prevent external modification
	entries := make([]TreeEntry, len(t.entries))
	copy(entries, t.entries)
	return entries
}

// Returns the SHA-1 hash of the tree
func (t *Tree) Hash() string {
	if t == nil {
		return ""
	}
	return t.hash
}

// Checks if the tree is empty or has no entries
func (t *Tree) IsEmpty() bool {
	return t == nil || len(t.entries) == 0
}

// Returns a string representation of the tree
func (t *Tree) String() string {
	if t == nil {
		return "Tree{nil}"
	}

	return fmt.Sprintf("Tree{hash: %s, entries: %d}", t.hash[:8], len(t.entries))
}

// Compares two trees for equality based on their hash
func (t *Tree) Equals(other *Tree) bool {
	if t == nil || other == nil {
		return t == other
	}

	return t.hash == other.hash
}

// Creates a deep clone of the tree
func (t *Tree) Clone() *Tree {
	if t == nil || t.BaseObject == nil {
		if tree, err := BuildTree(nil); err == nil {
			return tree
		}
		return nil
	}

	entries := make([]TreeEntry, len(t.entries))
	copy(entries, t.entries)
	clone, _ := BuildTree(entries)
	return clone
}

// updateContent sorts and and rebuilds the serialized object content
func (t *Tree) updateContent() {
	sort.Slice(t.entries, func(i, j int) bool {
		return t.entries[i].Name < t.entries[j].Name
	})

	t.objectContent = t.serializeEntries()
}

// serializeEntries encodes a slice of entries into Git's raw tree format: "<mode> <name>\0<20-byte raw sha1>"
func (t *Tree) serializeEntries() []byte {
	var buffer bytes.Buffer
	for _, entry := range t.entries {
		buffer.WriteString(fmt.Sprintf("%s %s\x00", entry.Mode, entry.Name))

		hash, _ := hex.DecodeString(entry.Hash)

		buffer.Write(hash)
	}

	return buffer.Bytes()
}

// deserializeEntries decodes raw Git tree data back into TreeEntry structs
func deserializeEntries(content []byte) ([]TreeEntry, error) {
	var entries []TreeEntry

	for i := 0; i < len(content); {
		// find the next null byte
		nullIndex := bytes.IndexByte(content[i:], 0)
		if nullIndex == -1 {
			break
		}
		nullIndex += i

		// extract the mode and name
		header := string(content[i:nullIndex])
		headerParts := strings.SplitN(header, " ", 2)
		if len(headerParts) != 2 {
			return nil, fmt.Errorf("invalid tree entry header format: %s", header)
		}
		mode, name := headerParts[0], headerParts[1]

		// extract the 20-byte hash
		hashStart := nullIndex + 1
		hashEnd := hashStart + 20
		if hashEnd > len(content) {
			return nil, fmt.Errorf("incomplete hash in tree entry")
		}
		hash := hex.EncodeToString(content[hashStart:hashEnd])

		// append the entry
		entries = append(entries, TreeEntry{
			Mode: mode,
			Name: name,
			Hash: hash,
		})

		// move to the next entry
		i = hashEnd
	}

	return entries, nil
}

/*
validateEntry checks that an entry is valid according to Git rules:
  - Name is non-empty and cannot contain '/'
  - Hash is exactly 40 hex chars
  - Mode is one of Git's supported ones (file, executable, directory)
*/
func validateEntry(entry TreeEntry) error {
	if entry.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if strings.Contains(entry.Name, "/") {
		return fmt.Errorf("name cannot contain '/' (use subtrees)")
	}
	if len(entry.Hash) != 40 {
		return fmt.Errorf("hash must be 40 hex chars (got %d)", len(entry.Hash))
	}
	switch entry.Mode {
	case "100644", "100755", "40000": // file, executable, directory
	default:
		return fmt.Errorf("invalid mode %s", entry.Mode)
	}
	return nil
}
