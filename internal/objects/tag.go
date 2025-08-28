package objects

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/OmprakashD20/strata/internal/utils"
)

// Tag represents a Git tag object(annotated-tag)
// Provides human-readable name for specific commit
type Tag struct {
	*BaseObject
	ObjectHash string // sha-1 of the object being tagged
	TagType    string // type of object being tagged
	TagName    string // tag name
	Tagger     *User  // tagger name, email and timestamp when tag was created
	Message    string // tag annotation
}

// Build a new tag object
func BuildTag(objectHash, tagType, tagName, message string, tagger *User) (*Tag, error) {
	tag := &Tag{
		ObjectHash: objectHash,
		TagType:    tagType,
		TagName:    tagName,
		Tagger:     tagger,
		Message:    message,
	}

	// validate the tag
	if err := validateTag(tag); err != nil {
		return nil, err
	}

	content := serializeTag(tag)
	tag.BaseObject = &BaseObject{
		objectType:    TagType,
		objectContent: content,
	}

	return tag, nil
}

// ParseTag creates a new tag from serialized tag content
func ParseTag(content []byte) (*Tag, error) {
	tag, err := deserializeTag(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tag: %w", err)
	}

	tag.BaseObject = &BaseObject{
		objectType:    TagType,
		objectContent: bytes.Clone(content),
	}

	return tag, nil
}

// Returns a string representation of the tag
func (t *Tag) String() string {
	if t == nil {
		return "Tag{nil}"
	}

	return fmt.Sprintf("Tag{name: %s, hash: %s, object: %s (%s), tagger: %s, message: %q}",
		t.TagName,
		t.Hash()[:8],
		t.ObjectHash[:8],
		t.TagType,
		t.Tagger,
		t.Message,
	)
}

func serializeTag(t *Tag) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("object %s\n", t.ObjectHash))
	buffer.WriteString(fmt.Sprintf("tag %s\n", t.TagType))
	buffer.WriteString(fmt.Sprintf("name %s\n", t.TagName))
	buffer.WriteString(fmt.Sprintf("tagger %s\n", t.Tagger))
	buffer.WriteString("\n")
	buffer.WriteString(t.Message)

	return buffer.Bytes()
}

func deserializeTag(content []byte) (*Tag, error) {
	lines := strings.Split(string(content), "\n")
	msgIndex := -1

	tag := &Tag{}

	for i, line := range lines {
		if line == "" {
			msgIndex = i + 1
			break
		}

		switch {
		case strings.HasPrefix(line, "object "):
			tag.ObjectHash = strings.TrimPrefix(line, "object ")
		case strings.HasPrefix(line, "tag "):
			tag.TagType = strings.TrimPrefix(line, "tag ")
		case strings.HasPrefix(line, "name "):
		tag.TagName = strings.TrimPrefix(line, "name ")
		case strings.HasPrefix(line, "tagger "):
			user, err := parseUser(strings.TrimPrefix(line, "tagger "))
			if err != nil {
				return nil, err
			}
			tag.Tagger = user
		}
	}

	if msgIndex != -1 && msgIndex < len(lines) {
		tag.Message = strings.Join(lines[msgIndex:], "\n")
	}

	if err := validateTag(tag); err != nil {
		return nil, err
	}

	return tag, nil
}

// Checks that if a tag is valid
func validateTag(tag *Tag) error {
	if len(tag.ObjectHash) != 40 {
		return fmt.Errorf("invalid object")
	}
	if tag.TagType == "" {
		return fmt.Errorf("type required")
	}
	if tag.TagName == "" {
		return fmt.Errorf("name required")
	}
	if tag.Tagger == nil {
		return fmt.Errorf("tagger required")
	}
	if err := validateUser(tag.Tagger); err != nil {
		return err
	}
	return nil
}

type TagBuilder struct {
	objectHash string
	tagType    string
	tagName    string
	tagger     *User
	message    string
}

func NewTagBuilder() *TagBuilder {
	return &TagBuilder{
		tagger: &User{},
	}
}

func (b *TagBuilder) WithObject(objectHash, tagType string) *TagBuilder {
	b.objectHash = objectHash
	b.tagType = tagType
	return b
}

func (b *TagBuilder) WithName(name string) *TagBuilder {
	b.tagName = name
	return b
}

func (b *TagBuilder) WithTagger(info string) *TagBuilder {
	b.tagger.Info = info
	b.tagger.Timestamp = time.Now().Unix()
	b.tagger.TZ = utils.FormatTimezoneOffset(time.Now())
	return b
}

func (b *TagBuilder) WithMessage(msg string) *TagBuilder {
	b.message = msg
	return b
}

func (b *TagBuilder) Build() (*Tag, error) {
	return BuildTag(b.objectHash, b.tagType, b.tagName, b.message, b.tagger)
}

// Ensure Tag implements GitObject
var _ GitObject = (*Tag)(nil)
