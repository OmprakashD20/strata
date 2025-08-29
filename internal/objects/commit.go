package objects

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/OmprakashD20/strata/internal/utils"
)

// Commit represents a Git commit object
// Contains metadata about a specific version including tree snapshot, parents, author info, and message
type Commit struct {
	*BaseObject
	TreeHash     string   // sha-1 hash of the tree object (directory snapshot)
	ParentHashes []string // sha-1 hashes of parent commits
	Author       *User
	Committer    *User
	Message      string // commit message
}

// Build a new Commit object
func BuildCommit(treeHash string, parentHashes []string, author, committer *User, message string) (*Commit, error) {
	if committer == nil {
		committer = author
	}

	commit := &Commit{
		TreeHash:     treeHash,
		ParentHashes: parentHashes,
		Author:       author,
		Committer:    committer,
		Message:      message,
	}

	// validate the fields
	if err := validateCommit(commit); err != nil {
		return nil, err
	}

	content := serializeCommit(commit)
	commit.BaseObject = &BaseObject{
		objectType:    CommitType,
		objectContent: content,
	}

	return commit, nil
}

// ParseCommit creates a new Commit from serialized commit content
func ParseCommit(content []byte) (*Commit, error) {
	commit, err := deserializeCommit(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse commit: %v", err)
	}

	commit.BaseObject = &BaseObject{
		objectType:    CommitType,
		objectContent: bytes.Clone(content),
	}

	return commit, nil

}

// AddParent adds a new parent commit hash
func (c *Commit) AddParent(parentHash string) error {
	if len(parentHash) != 40 {
		return fmt.Errorf("invalid parent hash: %s", parentHash)
	}

	// check for duplicates
	if slices.Contains(c.ParentHashes, parentHash) {
		return fmt.Errorf("parent hash already exists: %s", parentHash)
	}

	c.ParentHashes = append(c.ParentHashes, parentHash)

	c.objectContent = serializeCommit(c)
	return nil
}

// Checks if the commit has no parent commits
func (c *Commit) IsRootCommit() bool {
	return len(c.ParentHashes) == 0
}

// Checks if the commit is resulted from a merge
func (c *Commit) IsMergeCommit() bool {
	return len(c.ParentHashes) > 1
}

// Returns the first parent of the commit
func (c *Commit) FirstParent() *string {
	if len(c.ParentHashes) == 0 {
		return nil
	}
	return &c.ParentHashes[0]
}

// Returns the commit message header
func (c *Commit) CommitHeader() string {
	if c == nil {
		return ""
	}

	lines := strings.SplitN(c.Message, "\n", 2)

	if len(lines) == 0 {
		return ""
	}

	return lines[0]
}

// Returns a string representation of the commit
func (c *Commit) String() string {
	if c == nil {
		return "Commit{nil}"
	}

	parentInfo := "none"
	if len(c.ParentHashes) == 1 {
		parentInfo = c.ParentHashes[0][:8]
	} else if len(c.ParentHashes) > 1 {
		parentInfo = fmt.Sprintf("%d parents", len(c.ParentHashes))
	}

	return fmt.Sprintf("Commit{hash: %s, tree: %s, parents: %s, author: %s, committer: %s, message: %.30q}", c.Hash()[:8], c.TreeHash[:8], parentInfo, c.Author, c.Committer, c.CommitHeader())

}

func serializeCommit(c *Commit) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("tree %s\n", c.TreeHash))
	for _, parent := range c.ParentHashes {
		buffer.WriteString(fmt.Sprintf("parent %s\n", parent))
	}
	buffer.WriteString(fmt.Sprintf("author %s\n", c.Author))
	buffer.WriteString(fmt.Sprintf("committer %s\n", c.Committer))
	buffer.WriteString("\n")
	buffer.WriteString(c.Message)

	return buffer.Bytes()
}

func deserializeCommit(content []byte) (*Commit, error) {
	lines := strings.Split(string(content), "\n")
	msgIndex := -1

	commit := &Commit{
		ParentHashes: make([]string, 0),
	}

	for i, line := range lines {
		if line == "" {
			msgIndex = i + 1
			break
		}

		switch {
		case strings.HasPrefix(line, "tree "):
			commit.TreeHash = strings.TrimPrefix(line, "tree ")
		case strings.HasPrefix(line, "parent "):
			commit.ParentHashes = append(
				commit.ParentHashes,
				strings.TrimPrefix(line, "parent "),
			)
		case strings.HasPrefix(line, "author "):
			user, err := parseUser(strings.TrimPrefix(line, "author "))
			if err != nil {
				return nil, err
			}
			commit.Author = user
		case strings.HasPrefix(line, "committer "):
			user, err := parseUser(strings.TrimPrefix(line, "committer "))
			if err != nil {
				return nil, err
			}
			commit.Committer = user
		}
	}

	if msgIndex != -1 && msgIndex < len(lines) {
		commit.Message = strings.Join(lines[msgIndex:], "\n")
	}

	if err := validateCommit(commit); err != nil {
		return nil, err
	}

	return commit, nil
}

// Checks that a commit is valid
func validateCommit(c *Commit) error {
	if c.TreeHash == "" {
		return fmt.Errorf("tree hash required")
	}
	if len(c.TreeHash) != 40 {
		return fmt.Errorf("invalid tree hash length: %d", len(c.TreeHash))
	}
	if err := validateUser(c.Author); err != nil {
		return fmt.Errorf("author required: %v", err)
	}
	if c.Message == "" {
		return fmt.Errorf("commit message required")
	}
	for _, p := range c.ParentHashes {
		if len(p) != 40 {
			return fmt.Errorf("invalid parent hash: %s", p)
		}
	}
	return nil
}

type CommitBuilder struct {
	treeHash     string
	parentHashes []string
	author       *User
	committer    *User
	message      string
}

func NewCommitBuilder() *CommitBuilder {
	return &CommitBuilder{
		parentHashes: make([]string, 0),
		author:       &User{},
	}
}

func (b *CommitBuilder) WithTree(tree string) *CommitBuilder {
	b.treeHash = tree
	return b
}

func (b *CommitBuilder) WithParent(p string) *CommitBuilder {
	b.parentHashes = append(b.parentHashes, p)
	return b
}

func (b *CommitBuilder) WithAuthor(info string) *CommitBuilder {
	b.author.Info = info
	b.author.Timestamp = time.Now().Unix()
	b.author.TZ = utils.FormatTimezoneOffset(time.Now())
	return b
}

func (b *CommitBuilder) WithCommitter(info string) *CommitBuilder {
	if b.committer == nil {
		b.committer = &User{}
	}
	b.committer.Info = info
	b.committer.Timestamp = time.Now().Unix()
	b.committer.TZ = utils.FormatTimezoneOffset(time.Now())
	return b
}

func (b *CommitBuilder) WithMessage(message string) *CommitBuilder {
	b.message = message
	return b
}

func (b *CommitBuilder) Build() (*Commit, error) {
	return BuildCommit(b.treeHash, b.parentHashes, b.author, b.committer, b.message)
}

// Ensure Commit implements GitObject
var _ GitObject = (*Commit)(nil)
