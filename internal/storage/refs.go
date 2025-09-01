package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OmprakashD20/strata/internal/utils"
)

type RefManager struct {
	gitDir string // git directory path
}

// NewRefManager creates a new RefManager instance with the specified git directory
func NewRefManager(gitDir string) *RefManager {
	return &RefManager{
		gitDir: gitDir,
	}
}

// ReadRef reads the content of a git ref and returns the commit hash
func (r *RefManager) ReadRef(ref string) (string, error) { // todo: avoid any circular reference
	refPath := filepath.Join(r.gitDir, ref)

	data, err := os.ReadFile(refPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ref: %v", err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return "", fmt.Errorf("empty ref: %s", ref)
	}

	// check if it is a symbolic ref(HEAD)
	if head, ok := strings.CutPrefix(content, "ref: "); ok {
		return r.ReadRef(head)
	}

	// check if the content is a valid hash
	if !utils.IsValidHash(content) {
		return "", fmt.Errorf("invalid hash: %v", content)
	}

	return content, nil

}

// UpdateRef updates a git ref with the specified commit hash
func (r *RefManager) UpdateRef(ref, hash string) error {
	if !utils.IsValidHash(hash) {
		return fmt.Errorf("invalid hash: %v", hash)
	}

	refPath := filepath.Join(r.gitDir, ref)
	lockFile := refPath + ".lock"

	if err := os.MkdirAll(filepath.Dir(refPath), 0755); err != nil {
		return fmt.Errorf("failed to create ref directory: %v", err)
	}

	data := []byte(hash + "\n")
	if err := os.WriteFile(lockFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write lock file: %v", err)
	}

	if err := os.Rename(lockFile, refPath); err != nil {
		return fmt.Errorf("failed to rename lock file: %v", err)
	}

	return nil
}

// DeleteRef deletes a git ref, prevents direct deletion of HEAD
func (r *RefManager) DeleteRef(ref string) error {
	refPath := filepath.Join(r.gitDir, ref)

	// prevent deleting HEAD directly
	if filepath.Clean(ref) == "HEAD" {
		return fmt.Errorf("cannot delete HEAD directly, use SetHEAD instead")
	}
	
	// delete the ref
	err := os.Remove(refPath)
	if os.IsNotExist(err) {
		return nil 
	}
	if err != nil {
		return fmt.Errorf("failed to delete ref %s: %v", ref, err)
	}
	
	return nil
}

// SetHEAD sets the HEAD ref to point to a commit or branch
func (r *RefManager) SetHEAD(target string) error {
	headPath := filepath.Join(r.gitDir, "HEAD")
	lockFile := filepath.Join(r.gitDir, "HEAD.lock")

	var content string

	// check if the target is a branch or a commit
	if utils.IsValidHash(target) {
		// DETACHED HEAD - points directly to a commit
		content = fmt.Sprintf("%s\n", target)
	} else {
		// points to a branch
		// check if the branch exists
		branchRef := filepath.Join("refs", "heads", target)
		if !r.Exists(branchRef) {
			return fmt.Errorf("branch does not exist: %v", target)
		}
		content = fmt.Sprintf("ref: %s\n", branchRef)
	}

	if err := os.WriteFile(lockFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write lock file: %v", err)
	}

	if err := os.Rename(lockFile, headPath); err != nil {
		return fmt.Errorf("failed to rename lock file: %v", err)
	}

	return nil
}

// CurrentBranch returns the name of the current branch or an error if in detached HEAD state
func (r *RefManager) CurrentBranch() (string, error) {
	headPath := filepath.Join(r.gitDir, "HEAD")

	data, err := os.ReadFile(headPath)
	if err != nil {
		return "", err
	}

	head := strings.TrimSpace(string(data))
	if head == "" {
		return "", fmt.Errorf("invalid HEAD: empty content")
	}

	if branch, ok := strings.CutPrefix(head, "ref: refs/heads/"); ok {
		return branch, nil
	}

	if utils.IsValidHash(head) {
		return "", fmt.Errorf("detached HEAD")
	}

	return "", fmt.Errorf("invalid HEAD: %s", head)
}

// ListBranches returns a list of all branches in the repository
func (r *RefManager) ListBranches() ([]string, error) {
	base := filepath.Join(r.gitDir, "refs")
	branchesDir := filepath.Join(base, "heads")
	return listRefs(base, branchesDir)
}

// ListTags returns a list of all tags in the repository
func (r *RefManager) ListTags() ([]string, error) {
	base := filepath.Join(r.gitDir, "refs")
	tagsDir := filepath.Join(base, "tags")
	return listRefs(base, tagsDir)
}

// Exists checks if a git ref exists in the repository
func (r *RefManager) Exists(ref string) bool {
	refPath := filepath.Join(r.gitDir, ref)
	_, err := os.Stat(refPath)

	return err == nil
}

// Recursively lists all refs under a given git directory.
func listRefs(base, dir string) ([]string, error) {
	var refs []string
	entries, err := os.ReadDir(dir)

	if os.IsNotExist(err) {
		return []string{}, nil // empty refs
	}

	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(dir, entry.Name())
		relPath, err := filepath.Rel(base, entryPath)
		if err != nil {
			return nil, err
		}
		if entry.IsDir() {
			subRefs, err := listRefs(base, entryPath)
			if err != nil {
				return nil, err
			}
			refs = append(refs, subRefs...)
		} else {
			// append the ref with its relative path
			refs = append(refs, relPath)
		}
	}

	// sort the refs
	sort.Strings(refs)

	return refs, nil
}
