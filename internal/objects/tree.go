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
}

// BuildTree constructs a Tree from a slice of Tree entries
func BuildTree(entries []TreeEntry) (*Tree, error) {
	tree := &Tree{
		BaseObject: &BaseObject{
			objectType: TreeType,
		},
		entries: entries,
	}

	// validate the tree entries
	if err := validateTree(tree); err != nil {
		return nil, err
	}

	tree.objectContent = serializeTree(tree)

	return tree, nil
}

// ParseTree reconstructs a Tree from its serialized tree content
func ParseTree(content []byte) (*Tree, error) {
	tree, err := deserializeTree(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tree: %v", err)
	}

	tree.BaseObject = &BaseObject{
		objectType:    TreeType,
		objectContent: bytes.Clone(content),
	}

	return tree, nil
}

// MakeEntry adds or updates an entry in the tree
func (t *Tree) MakeEntry(mode, name, hash string) error {
	entry := TreeEntry{Mode: mode, Name: name, Hash: hash}

	if err := validateTree(t); err != nil {
		return err
	}

	// replace if exists
	for i, e := range t.entries {
		if e.Name == name {
			t.entries[i] = entry
			t.objectContent = serializeTree(t)
			return nil
		}
	}

	// else, append
	t.entries = append(t.entries, entry)
	t.objectContent = serializeTree(t)

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

// Checks if the tree is empty or has no entries
func (t *Tree) IsEmpty() bool {
	return t == nil || len(t.entries) == 0
}

// Returns a string representation of the tree
func (t *Tree) String() string {
	if t == nil {
		return "Tree{nil}"
	}

	return fmt.Sprintf("Tree{hash: %s, entries: %d}", t.Hash()[:8], len(t.entries))
}

// Encodes the slice of entries into raw tree entry format: "<mode> <name>\0<20-byte raw sha1>"
func serializeTree(t *Tree) []byte {
	sort.Slice(t.entries, func(i, j int) bool {
		return t.entries[i].Name < t.entries[j].Name
	})

	var buffer bytes.Buffer
	for _, entry := range t.entries {
		buffer.WriteString(fmt.Sprintf("%s %s\x00", entry.Mode, entry.Name))

		hash, _ := hex.DecodeString(entry.Hash)

		buffer.Write(hash)
	}

	return buffer.Bytes()
}

// Decodes raw Tree data back into Tree struct
func deserializeTree(content []byte) (*Tree, error) {
	tree := &Tree{
		entries: make([]TreeEntry, 0),
	}

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
		tree.entries = append(tree.entries, TreeEntry{
			Mode: mode,
			Name: name,
			Hash: hash,
		})

		// move to the next entry
		i = hashEnd
	}

	return tree, nil
}

/*
validateTree checks that a tree's entries are valid, according to Git rules:
  - Name is non-empty and cannot contain '/'
  - Hash is exactly 40 hex chars
  - Mode is one of Git's supported ones (file, executable, directory)
*/
func validateTree(tree *Tree) error {
	for _, entry := range tree.Entries() {
		var errorMsgs []string

		// Validate Name
		if entry.Name == "" {
			errorMsgs = append(errorMsgs, "name cannot be empty")
		} else if strings.Contains(entry.Name, "/") {
			errorMsgs = append(errorMsgs, "name cannot contain '/' (use subtrees)")
		}

		// Validate Hash
		if len(entry.Hash) != 40 {
			errorMsgs = append(errorMsgs, fmt.Sprintf("hash must be 40 hex chars (got %d)", len(entry.Hash)))
		}

		// Validate Mode
		switch entry.Mode {
		case "100644", "100755", "40000": // file, executable, directory
		default:
			errorMsgs = append(errorMsgs, fmt.Sprintf("invalid mode %s", entry.Mode))
		}

		if len(errorMsgs) > 0 {
			return fmt.Errorf("invalid tree entry %s: %s", entry.Name, strings.Join(errorMsgs, "; "))
		}
	}

	// Return nil if everything is valid
	return nil
}

// Ensure Tree implements GitObject
var _ GitObject = (*Tree)(nil)
