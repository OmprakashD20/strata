package objects

import (
	"bytes"
	"fmt"
	"strings"
)

// Blob represents the file's content in Git
// Blob stores the raw data of a file without any metadata like filename or permissions
type Blob struct {
	*BaseObject
}

// Create a new Blob object with the given content
func NewBlob(content []byte) *Blob {
	blob := &Blob{
		BaseObject: &BaseObject{
			objectType:    BlobType,
			objectContent: bytes.Clone(content),
		},
	}

	return blob
}

// Returns a string representation of the blob
func (b *Blob) String() string {
	if b == nil || b.BaseObject == nil {
		return "Blob{nil}"
	}

	content := string(b.Content())
	if len(content) > 100 {
		runes := []rune(content)
		content = string(runes[:100]) + "..."
	}

	content = strings.ReplaceAll(content, "\n", "\\n")

	return fmt.Sprintf("Blob{Hash: %s, Size: %d, Content: %q}", b.Hash()[:8], len(b.Content()), content)
}

// Returns the size of the blob content in bytes
func (b *Blob) Size() int {
	if b == nil || b.BaseObject == nil {
		return 0
	}

	return len(b.Content())
}

// Checks if the blob is empty
func (b *Blob) IsEmpty() bool {
	return b.Size() == 0
}

// ensures Blob implements the GitObject interface
var _ GitObject = (*Blob)(nil)
