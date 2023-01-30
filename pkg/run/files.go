package run

import (
	"os"
)

// FileAccessor is an interface defining a file with given name and content
// to be used within a Runner, and that abstracts the logic with which
// content is retrieved.
type FileAccessor interface {
	Name() string
	Content() ([]byte, error)
}

type localFileAccessor struct {
	path string
	name string
}

// NewLocalFileAccessor creates a FileAccessor of which content is the content
// of a file in the local filesystem
func NewLocalFileAccessor(name, path string) *localFileAccessor {
	return &localFileAccessor{name: name, path: path}
}

func (l *localFileAccessor) Name() string {
	return l.name
}

func (l *localFileAccessor) Content() ([]byte, error) {
	return os.ReadFile(l.path)
}

type memFileAccessor struct {
	name    string
	content []byte
}

// NewStringFileAccessor creates a FileAccessor that has a string as its content
func NewStringFileAccessor(name, content string) *memFileAccessor {
	return &memFileAccessor{name: name, content: ([]byte)(content)}
}

// NewBytesFileAccessor creates a FileAccessor that has a byte buf as its content
func NewBytesFileAccessor(name string, content []byte) *memFileAccessor {
	return &memFileAccessor{name: name, content: content}
}

func (l *memFileAccessor) Name() string {
	return l.name
}

func (l *memFileAccessor) Content() ([]byte, error) {
	return ([]byte)(l.content), nil
}
