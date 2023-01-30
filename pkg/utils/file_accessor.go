package utils

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"time"

	"go.uber.org/multierr"
)

type FileAccessor interface {
	Name() string
	Content() ([]byte, error)
}

type localFileAccessor struct {
	path string
	name string
}

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

func NewStringFileAccessor(name, content string) *memFileAccessor {
	return &memFileAccessor{name: name, content: ([]byte)(content)}
}

func NewBytesFileAccessor(name string, content []byte) *memFileAccessor {
	return &memFileAccessor{name: name, content: content}
}

func (l *memFileAccessor) Name() string {
	return l.name
}

func (l *memFileAccessor) Content() ([]byte, error) {
	return ([]byte)(l.content), nil
}

func TarFiles(w io.Writer, files ...FileAccessor) (err error) {
	tw := tar.NewWriter(w)
	defer func() {
		err = multierr.Append(err, tw.Close())
	}()

	for _, file := range files {
		fileContent, err := file.Content()
		if err != nil {
			return err
		}

		// create a new file header
		header := &tar.Header{
			Name:     file.Name(),
			ModTime:  time.Now(),
			Mode:     int64(0777),
			Typeflag: tar.TypeReg,
			Size:     int64(len(fileContent)),
		}

		// write the header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// copy file data into tar writer
		if _, err := io.Copy(tw, bytes.NewReader(fileContent)); err != nil {
			return err
		}
	}

	return nil
}
