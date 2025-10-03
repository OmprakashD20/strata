package repository

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/OmprakashD20/strata/internal/objects"
	"github.com/OmprakashD20/strata/internal/storage"
	"github.com/OmprakashD20/strata/internal/utils"
)

type Repository struct {
	WorkDir      string
	GitDir       string
	ObjectStore  *storage.ObjectStore
	RefManager   *storage.RefManager
	IndexManager *IndexManager
}

// Creates a new Repository instance from an existing git repository
func NewRepository(workDir string) (*Repository, error) {
	if workDir == "" {
		return nil, fmt.Errorf("working directory cannot be empty")
	}

	// check if working directory exists
	if _, err := os.Stat(workDir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("working directory does not exist: %s", workDir)
		}
		return nil, fmt.Errorf("cannot access working directory: %v", err)
	}

	gitDir := filepath.Join(workDir, ".git")

	// check if .git exists
	if _, err := os.Stat(gitDir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not a git repository: %s", workDir)
		}
		return nil, fmt.Errorf("cannot access .git directory: %v", err)
	}

	indexManager, err := NewIndexManager(workDir, gitDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize index manager: %v", err)
	}

	return &Repository{
		WorkDir:      workDir,
		GitDir:       gitDir,
		ObjectStore:  storage.NewObjectStore(gitDir),
		RefManager:   storage.NewRefManager(gitDir),
		IndexManager: indexManager,
	}, nil
}

// Initializes a new Git repository in the specified working directory
func InitRepository(workDir string) (*Repository, error) {
	if workDir == "" {
		return nil, fmt.Errorf("working directory cannot be empty")
	}

	// create working directory if it doesn't exist
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %v", err)
	}

	gitDir := filepath.Join(workDir, ".git")

	// check if .git already exists
	if _, err := os.Stat(gitDir); err == nil {
		return nil, fmt.Errorf("already a git repository: %s", workDir)
	}

	// create .git directory structure
	dirs := []string{
		gitDir,
		filepath.Join(gitDir, "objects"),
		filepath.Join(gitDir, "refs"),
		filepath.Join(gitDir, "refs", "heads"),
		filepath.Join(gitDir, "refs", "tags"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// create HEAD file pointing to master branch
	// we point to refs/heads/master even though it doesn't exist yet, the branch will be created on first commit
	path := filepath.Join(gitDir, "HEAD")
	content := "ref: refs/heads/master\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to create HEAD file: %v", err)
	}

	indexManager, err := NewIndexManager(workDir, gitDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize index manager: %v", err)
	}

	return &Repository{
		WorkDir:      workDir,
		GitDir:       gitDir,
		ObjectStore:  storage.NewObjectStore(gitDir),
		RefManager:   storage.NewRefManager(gitDir),
		IndexManager: indexManager,
	}, nil
}

// AddFile stages a file for commit by adding it to the index
func (r *Repository) AddFile(path string) error {
	// add file to index
	blob, err := r.IndexManager.AddFile(path)
	if err != nil {
		return err
	}

	// write blob to object store
	if err := r.ObjectStore.WriteObject(blob); err != nil {
		return fmt.Errorf("failed to write blob to object store: %v", err)
	}

	return nil
}

// CreateCommit creates a new commit from the current index state
func (r *Repository) CreateCommit(message, author, committer string) (string, error) {
	// load the index
	if err := r.IndexManager.Index().Load(); err != nil {
		return "", fmt.Errorf("failed to load index: %v", err)
	}

	// check if there are any staged changes
	if len(r.IndexManager.Index().Entries()) == 0 {
		return "", fmt.Errorf("nothing to commit (staging area is empty)")
	}

	// build tree from index
	tree, err := r.IndexManager.BuildTree()
	if err != nil {
		return "", fmt.Errorf("failed to build tree: %v", err)
	}

	// get parent commits (if exists)
	var parentHashes []string
	if parentHash, err := r.RefManager.ReadRef("HEAD"); err == nil {
		parentHashes = append(parentHashes, parentHash)
	}

	// build commit
	cb := objects.NewCommitBuilder().
		WithTree(tree.Hash()).
		WithAuthor(author).
		WithMessage(message)

	if committer != "" {
		cb = cb.WithCommitter(committer)
	}

	for _, parentHash := range parentHashes {
		cb = cb.WithParent(parentHash)
	}

	commit, err := cb.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build commit: %v", err)
	}

	// write tree object to object store first
	if err := r.ObjectStore.WriteObject(tree); err != nil {
		return "", fmt.Errorf("failed to write tree object: %v", err)
	}

	// write commit object to object store
	if err := r.ObjectStore.WriteObject(commit); err != nil {
		return "", fmt.Errorf("failed to write commit object: %v", err)
	}

	// update current branch to point to new commit
	currentBranch, err := r.RefManager.CurrentBranch()
	if err != nil {
		// first commit or detached HEAD
		// read HEAD to see if it's a symbolic ref
		path := filepath.Join(r.GitDir, "HEAD")
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to read HEAD: %v", err)
		}

		var head string
		if head = strings.TrimSpace(string(content)); head == "" {
			return "", fmt.Errorf("HEAD file is empty")
		}
		if branchRef, ok := strings.CutPrefix(head, "ref: "); ok {
			// symbolic ref - create the branch
			if err := r.RefManager.UpdateRef(branchRef, commit.Hash()); err != nil {
				return "", fmt.Errorf("failed to update HEAD: %v", err)
			}
		} else {
			// detached HEAD - update HEAD directly
			if err := r.RefManager.UpdateRef("HEAD", commit.Hash()); err != nil {
				return "", fmt.Errorf("failed to update HEAD: %v", err)
			}
		}
	} else {
		// update current branch
		branchRef := filepath.Join("refs", "heads", currentBranch)
		if err := r.RefManager.UpdateRef(branchRef, commit.Hash()); err != nil {
			return "", fmt.Errorf("failed to update branch %s: %v", currentBranch, err)
		}
	}

	return commit.Hash(), nil
}

// Returns the status of files in the working directory and index
func (r *Repository) GetStatus() ([]StatusInfo, error) {
	return r.IndexManager.GetStatus()
}

// CreateBranch creates a new branch pointing to the specified commit
func (r *Repository) CreateBranch(name, startPoint string) error {
	if name == "" {
		return fmt.Errorf("branch name cannot be empty")
	}

	// validate branch name
	if strings.ContainsAny(name, " \t\n\r") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid branch name: %s", name)
	}

	branchRef := filepath.Join("refs", "heads", name)

	// check if the branch already exists
	if r.RefManager.Exists(branchRef) {
		return fmt.Errorf("branch '%s' already exists", name)
	}

	// determine the commit hash to point to
	var commitHash string
	var err error

	if startPoint == "" {
		// use current HEAD
		commitHash, err = r.RefManager.ReadRef("HEAD")
		if err != nil {
			return fmt.Errorf("failed to read HEAD: %v (no commits yet?)", err)
		}
	} else {
		// resolve the start point
		commitHash, err = r.resolveRef(startPoint)
		if err != nil {
			return fmt.Errorf("failed to resolve start point '%s': %v", startPoint, err)
		}
	}

	// check if the commit exists
	if !r.ObjectStore.Exists(commitHash) {
		return fmt.Errorf("commit does not exist: %s", commitHash)
	}

	// create the branch
	if err := r.RefManager.UpdateRef(branchRef, commitHash); err != nil {
		return fmt.Errorf("failed to create branch: %v", err)
	}

	return nil
}

// CheckoutBranch switches to the specified branch
func (r *Repository) CheckoutBranch(name string) error {
	if name == "" {
		return fmt.Errorf("branch name cannot be empty")
	}

	branchRef := filepath.Join("refs", "heads", name)

	// check if the branch exists
	if !r.RefManager.Exists(branchRef) {
		return fmt.Errorf("branch '%s' does not exist", name)
	}

	// get commit hash that the branch points to
	commitHash, err := r.RefManager.ReadRef(branchRef)
	if err != nil {
		return fmt.Errorf("failed to read branch ref: %v", err)
	}

	// check for uncommitted changes
	status, err := r.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get status: %v", err)
	}

	for _, s := range status {
		if s.WorkStatus == 'M' || s.IndexStatus == 'M' || s.IndexStatus == 'A' {
			return fmt.Errorf("uncommitted changes would be overwritten by checkout")
		}
	}

	// update HEAD to point to the branch
	if err := r.RefManager.SetHEAD(name); err != nil {
		return fmt.Errorf("failed to update HEAD: %v", err)
	}

	// checkout the commit
	if err := r.checkoutCommit(commitHash); err != nil {
		return fmt.Errorf("failed to checkout commit: %v", err)
	}

	return nil
}

// ListBranches returns all branches in the repository
func (r *Repository) ListBranches() ([]string, error) {
	refs, err := r.RefManager.ListBranches()
	if err != nil {
		return nil, err
	}

	var branches []string
	for _, ref := range refs {
		if strings.HasPrefix(ref, "heads/") {
			branch := strings.TrimPrefix(ref, "heads/")
			branches = append(branches, branch)
		}
	}

	return branches, nil
}

// CurrentBranch returns the current branch name
func (r *Repository) CurrentBranch() (string, error) {
	return r.RefManager.CurrentBranch()
}

// DeleteBranch deletes a branch
func (r *Repository) DeleteBranch(name string) error {
	if name == "" {
		return fmt.Errorf("branch name cannot be empty")
	}

	// prevent deleting current branch
	branch, err := r.RefManager.CurrentBranch()
	if err == nil && branch == name {
		return fmt.Errorf("cannot delete the branch '%s' which you are currently on", name)
	}

	ref := filepath.Join("refs", "heads", name)
	if !r.RefManager.Exists(ref) {
		return fmt.Errorf("branch '%s' not found", name)
	}

	return r.RefManager.DeleteRef(ref)
}

// GetCommit reads a commit object by hash
func (r *Repository) GetCommit(hash string) (*objects.Commit, error) {
	resolvedHash, err := r.resolveRef(hash)
	if err != nil {
		return nil, err
	}

	obj, err := r.ObjectStore.ReadObject(resolvedHash)
	if err != nil {
		return nil, fmt.Errorf("failed to read commit %s: %v", hash, err)
	}

	commit, ok := obj.(*objects.Commit)
	if !ok {
		return nil, fmt.Errorf("object %s is not a commit", resolvedHash)
	}

	return commit, nil
}

// GetCommitHistory returns commit history starting from hash
func (r *Repository) GetCommitHistory(hash string, limit int) ([]*objects.Commit, error) {
	if hash == "" {
		var err error
		hash, err = r.getCurrentCommit()
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		hash, err = r.resolveRef(hash)
		if err != nil {
			return nil, err
		}
	}

	var history []*objects.Commit
	visited := make(map[string]bool)
	commits := []string{hash}

	for len(commits) > 0 && (limit == 0 || len(history) < limit) {
		currentHash := commits[0]
		commits = commits[1:]

		if visited[currentHash] {
			continue
		}
		visited[currentHash] = true

		commit, err := r.GetCommit(currentHash)
		if err != nil {
			continue
		}

		history = append(history, commit)

		// add parents to queue (prepend to maintain order)
		commits = append(commit.ParentHashes, commits...)
	}

	return history, nil
}

// Returns the commit hash that HEAD points to
func (r *Repository) getCurrentCommit() (string, error) {
	hash, err := r.RefManager.ReadRef("HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to read HEAD: %v", err)
	}

	return hash, nil
}

// Populates the working directory with files from a commit
func (r *Repository) checkoutCommit(commitHash string) error {
	// read the commit object
	obj, err := r.ObjectStore.ReadObject(commitHash)
	if err != nil {
		return fmt.Errorf("failed to read commit %s: %v", commitHash, err)
	}

	commit, ok := obj.(*objects.Commit)
	if !ok {
		return fmt.Errorf("object is not a commit: %s", commitHash)
	}

	// read tree object
	treeObj, err := r.ObjectStore.ReadObject(commit.TreeHash)
	if err != nil {
		return fmt.Errorf("failed to read tree: %v", err)
	}

	tree, ok := treeObj.(*objects.Tree)
	if !ok {
		return fmt.Errorf("object is not a tree: %s", commit.TreeHash)
	}

	// clear working directory (except .git)
	if err := r.clearWorkingDirectory(); err != nil {
		return fmt.Errorf("failed to clear working directory: %v", err)
	}

	// clear the index
	if err := r.IndexManager.Clear(); err != nil {
		return fmt.Errorf("failed to clear index: %v", err)
	}

	// recursively checkout tree
	if err := r.checkoutTree(tree, ""); err != nil {
		return fmt.Errorf("failed to checkout tree: %v", err)
	}

	return nil
}

// Populates the working directory from a tree object
func (r *Repository) checkoutTree(tree *objects.Tree, prefix string) error {
	for _, entry := range tree.Entries() {
		path := filepath.Join(prefix, entry.Name)

		if entry.Mode == "40000" {
			// directory - recursively checkout subtree
			subtreeObj, err := r.ObjectStore.ReadObject(entry.Hash)
			if err != nil {
				return fmt.Errorf("failed to read subtree %s: %v", entry.Hash, err)
			}

			subtree, ok := subtreeObj.(*objects.Tree)
			if !ok {
				return fmt.Errorf("expected tree object, got %T", subtreeObj)
			}

			if err := r.checkoutTree(subtree, path); err != nil {
				return err
			}
		} else {
			// file - write to working directory and add to index
			if err := r.checkoutFile(entry, path); err != nil {
				return fmt.Errorf("failed to checkout file %s: %v", path, err)
			}
		}
	}

	return nil
}

// Writes a blob to the working directory and adds it to index
func (r *Repository) checkoutFile(entry objects.TreeEntry, relPath string) error {
	// read the blob object
	blobObj, err := r.ObjectStore.ReadObject(entry.Hash)
	if err != nil {
		return fmt.Errorf("failed to read blob: %v", err)
	}

	blob, ok := blobObj.(*objects.Blob)
	if !ok {
		return fmt.Errorf("expected blob object, got %T", blobObj)
	}

	fullPath := filepath.Join(r.WorkDir, relPath)

	// create parent directories
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// determine file mode
	var fileMode os.FileMode
	switch entry.Mode {
	case "100644":
		fileMode = 0644 // regular file
	case "100755":
		fileMode = 0755 // executable file
	case "120000":
		// symlink file
		target := string(blob.Content())
		if err := os.Symlink(target, fullPath); err != nil {
			return fmt.Errorf("failed to create symlink: %v", err)
		}
		// add to index
		if err := r.AddFile(fullPath); err != nil {
			return fmt.Errorf("failed to add symlink to index: %v", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported file mode: %s", entry.Mode)
	}

	// write the file
	if err := os.WriteFile(fullPath, blob.Content(), fileMode); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	// add to index
	if err := r.AddFile(fullPath); err != nil {
		return fmt.Errorf("failed to add file to index: %v", err)
	}

	return nil
}

// Removes all files from working directory except .git
func (r *Repository) clearWorkingDirectory() error {
	entries, err := os.ReadDir(r.WorkDir)
	if err != nil {
		return fmt.Errorf("failed to read working directory: %v", err)
	}

	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}

		path := filepath.Join(r.WorkDir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to remove %s: %v", path, err)
		}
	}

	status, err := r.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get status: %v", err)
	}
	for _, s := range status {
		if s.WorkStatus == '?' { // Untracked file
			return fmt.Errorf("untracked file %s would be overwritten by checkout", s.Path)
		}
	}

	return nil
}

// Resolves a ref name to a commit hash
func (r *Repository) resolveRef(ref string) (string, error) {
	// check if it's a valid commit hash
	if utils.IsValidHash(ref) && r.ObjectStore.Exists(ref) {
		return ref, nil
	}

	// try as branch
	branchRef := filepath.Join("refs", "heads", ref)
	if r.RefManager.Exists(branchRef) {
		return r.RefManager.ReadRef(branchRef)
	}

	// try as tag
	tagRef := filepath.Join("refs", "tags", ref)
	if r.RefManager.Exists(tagRef) {
		return r.RefManager.ReadRef(tagRef)
	}

	// try as short hash
	if len(ref) >= 4 && len(ref) < 40 {
		if hash, err := r.ObjectStore.ResolveHash(ref); err == nil {
			return hash, nil
		}
	}

	return "", fmt.Errorf("cannot resolve ref: %s", ref)
}
