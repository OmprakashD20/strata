package objects

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
)

type GitObject interface {
	Type() string
	Content() []byte
	Hash() string
	Serialize() ([]byte, error)
}

type BaseObject struct {
	ObjectType    string // blob, tree, commit, tag
	ObjectContent []byte
}

// Returns the type of the object (blob, tree, commit, tag)
func (obj *BaseObject) Type() string {
	return obj.ObjectType
}

// Returns the raw content of the object
func (obj *BaseObject) Content() []byte {
	return obj.ObjectContent
}

// Hash generates SHA-1 hash following Git's format: SHA-1(<type> <size>\0<content>)
func (obj *BaseObject) Hash() string {
	// create the object header <type> <size>\0
	header := fmt.Sprintf("%s %d\x00", obj.Type(), len(obj.Content()))

	// hash the header and content using SHA-1
	hasher := sha1.New()
	hasher.Write([]byte(header))
	hasher.Write(obj.Content())

	return hex.EncodeToString(hasher.Sum(nil))
}

// Serialize compresses the object for storage using zlib
func (obj *BaseObject) Serialize() ([]byte, error) {
	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)

	// write the header and content to the zlib writer
	header := fmt.Sprintf("%s %d\x00", obj.Type(), len(obj.Content()))
	if _, err := writer.Write([]byte(header)); err != nil {
		return nil, fmt.Errorf("failed to write header: %v", err)
	}

	if _, err := writer.Write(obj.ObjectContent); err != nil {
		return nil, fmt.Errorf("failed to write content: %v", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zlib writer: %v", err)
	}
	
	return buffer.Bytes(), nil
}

// Deserialize decompresses and reconstructs a GitObject from its serialized form
func Deserialize(data []byte) (GitObject, error){
	// decompress the data using zlib
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %v", err)
	}

	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompressed data: %v", err)
	}

	// split the header and content at the null byte
	nullIndex := bytes.IndexByte(decompressedData, 0)
	if nullIndex == -1 {
		return nil, fmt.Errorf("invalid object format: missing null byte")
	}

	// parse header: <type> <size>
	header := string(decompressedData[:nullIndex])
	content := decompressedData[nullIndex+1:]

	// parse the header to extract type and size
	headerParts := bytes.SplitN([]byte(header), []byte(" "), 2)
	if len(headerParts) != 2 {
		return nil, fmt.Errorf("invalid object header format: %s", header)
	}

	objectType := string(headerParts[0])

	// create the GitObject based on the type
	switch objectType {
	case BlobType:
		return NewBlob(content), nil
	default:
		return nil, fmt.Errorf("unsupported object type: %s", objectType)
	}
}

const (
	BlobType   = "blob"
	TreeType   = "tree"  
	CommitType = "commit"
	TagType    = "tag"
)