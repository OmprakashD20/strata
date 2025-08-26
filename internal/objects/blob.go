package objects

import "fmt"

// Blob represents the file's content in Git
// Blob stores the raw data of a file without any metadata like filename or permissions
type Blob struct {
	*BaseObject
	hash string
}

// Create a new Blob object with the given content
func NewBlob(content []byte) *Blob {
	if content == nil {
		content = []byte{}
	}

	blob := &Blob{
		BaseObject: &BaseObject{
			ObjectType:    BlobType,
			ObjectContent: make([]byte, len(content)),
		},
	}

	copy(blob.ObjectContent, content)
	blob.hash = blob.Hash()

	return blob
}

// Returns a string representation of the blob
func (b *Blob) String() string {
	if b == nil || b.BaseObject == nil {
		return "Blob{nil}"
	}

	content := string(b.Content())
	if len(content) > 100 {
		content = content[:100] + "..."
	}

	return fmt.Sprintf("Blob{Hash: %s, Size: %d, Content: %q}", b.hash[:8], len(b.Content()), content)
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

// Compares two blobs for equality based on their hash
func (b *Blob) Equals(blob *Blob) bool {
	if b == nil || blob == nil || b.BaseObject == nil || blob.BaseObject == nil {
		return false
	}

	return b.Hash() == blob.Hash()
}

// Creates a deep clone of the blob
func (b *Blob) Clone() *Blob {
	if b == nil || b.BaseObject == nil {
		return NewBlob(nil)
	}

	return NewBlob(b.Content())
}

// Returns the SHA-1 hash of the blob
func (b *Blob) Hash() string {
	if b == nil || b.BaseObject == nil {
		return ""
	}

	if b.hash != "" {
		return b.hash
	}

	b.hash = b.BaseObject.Hash()

	return b.hash
}

// ensures Blob implements the GitObject interface
var _ GitObject = (*Blob)(nil)
