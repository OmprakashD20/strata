package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/OmprakashD20/strata/internal/objects"
)

const (
	ObjectsDir = "objects"
)

const (
	CreateDirMode = 0755
	WriteFileMode = 0644
)

type ObjectStore struct {
	path string // path to the object store directory
}

// NewObjectStore creates a new ObjectStore instance
func NewObjectStore(gitDir string) *ObjectStore {
	return &ObjectStore{
		path: filepath.Join(gitDir, ObjectsDir),
	}
}

// WriteObject writes the git object to the object store
func (s *ObjectStore) WriteObject(obj objects.GitObject) error {
	hash := obj.Hash()

	// store the object in subdirectory: .git/objects/hash[:2]/hash[2:]
	dir := filepath.Join(s.path, hash[:2])
	file := filepath.Join(dir, hash[2:])

	// check if object already exists
	if fileExists(file) {
		return nil
	}

	// check if directory exists
	if err := os.MkdirAll(dir, CreateDirMode); err != nil {
		return fmt.Errorf("failed to create object directory: %v", err)
	}

	// serialize the git object
	data, err := obj.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize object: %v", err)
	}

	// write the serialized object to a temp file
	temp := file + ".tmp"
	if err := os.WriteFile(temp, data, WriteFileMode); err != nil {
		return fmt.Errorf("failed to write object file: %v", err)
	}

	// rename the temp file
	err = os.Rename(temp, file)
	if err != nil {
		return fmt.Errorf("failed to rename object file: %v", err)
	}

	return nil
}

// ReadObject reads the git object from the object store
func (s *ObjectStore) ReadObject(hash string) (objects.GitObject, error) {
	if len(hash) < 4 {
		return nil, fmt.Errorf("invalid: hash too short, %s", hash)
	}

	dir := filepath.Join(s.path, hash[:2])

	if len(hash) == 40 {
		file := filepath.Join(dir, hash[2:])
		return s.LoadObject(file)
	}

	if len(hash) == 2 {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read object directory: %v", err)
		}

		var matches []string
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), hash[2:]) {
				matches = append(matches, entry.Name())
			}
		}

		if len(matches) == 0 {
			return nil, fmt.Errorf("object not found: %s", hash)
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf("ambiguous hash: %s matches %v", hash, matches)
		}

		file := filepath.Join(dir, matches[0])
		return s.LoadObject(file)
	}

	return nil, fmt.Errorf("invalid: hash length, %s", hash)
}

// LoadObject loads an object from the object store
func (s *ObjectStore) LoadObject(file string) (objects.GitObject, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read object file: %v", err)
	}

	return objects.Deserialize(data)
}

func (s *ObjectStore) Exists(hash string) bool {
	_, err := s.ReadObject(hash)

	return err == nil
}

// List all objects in the object store
func (s *ObjectStore) ListObjects() ([]string, error) {
	var hashes []string

	entries, err := os.ReadDir(s.path)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 2 {
			continue
		}

		subdir := filepath.Join(s.path, entry.Name())
		subEntries, err := os.ReadDir(subdir)
		if err != nil {
			continue
		}

		for _, subEntry := range subEntries {
			if !subEntry.IsDir() {
				hash := entry.Name() + subEntry.Name()
				hashes = append(hashes, hash)
			}
		}
	}

	return hashes, nil
}

// Check if the file exists
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)

	return err == nil
}
