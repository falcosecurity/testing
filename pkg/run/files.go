/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

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
