package falco

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/jasondellaluce/falco-testing/pkg/utils"
	"github.com/sirupsen/logrus"
)

type execRunner struct {
	executable string
}

// writeToTempFile encodes a config to a newly-created temporary file
// and returns the file name and a callback for deleting the file,
// or a non-nil error in case of failure. The newly-created file should be
// deleted manually by invoking the returned callback.
func (e *execRunner) writeToTempFile(file utils.FileAccessor) (string, func() error, error) {
	c, err := file.Content()
	if err != nil {
		return "", nil, err
	}

	f, err := os.CreateTemp("", "falco-runner-")
	if err != nil {
		return "", nil, err
	}

	name := f.Name()
	logrus.WithField("file", file.Name()).WithField("tmpFile", name).Debugf("copying into temp file")
	n, err := f.Write(c)
	if err == nil || n < len(c) {
		err = f.Close()
		if err == nil {
			return name, func() error {
				logrus.WithField("tmpFile", name).Debugf("removing temp file")
				return os.Remove(name)
			}, nil
		}
		if n < len(c) {
			err = io.ErrShortWrite
		}
	}
	return "", nil, err
}

// NewExecutableRunner returns a Falco runner that runs a local executable binary
func NewExecutableRunner(executable string) Runner {
	return &execRunner{executable: executable}
}

func (e *execRunner) Run(ctx context.Context, options ...RunnerOption) error {
	opts := buildRunOptions(options...)

	// todo: find a better way for performing file name translation inside
	// a custom config file (this is quite horrible -- part 1)
	customConfigIndex := -1
	customConfigArgIndex := -1
	tmpFilesMap := make(map[string]string) // map from original to temp file names
	for i := 0; i < len(opts.args)-1; i++ {
		if opts.args[i] == "-c" {
			for j := 0; j < len(opts.files); j++ {
				if opts.files[j].Name() == opts.args[i+1] {
					customConfigIndex = j
					customConfigArgIndex = i + 1
					break
				}
			}
		}
	}

	for i, file := range opts.files {
		if i == customConfigIndex {
			// skip custom config files, as we'll edit and copy it later
			continue
		}
		// copy the file to a temporary location
		tempFileName, removeTmpFile, err := e.writeToTempFile(file)
		if err != nil {
			return err
		}
		defer removeTmpFile()

		// todo: find a better way for performing file name translation
		for i := 0; i < len(opts.args); i++ {
			if opts.args[i] == file.Name() {
				opts.args[i] = tempFileName
			}
		}
		tmpFilesMap[file.Name()] = tempFileName
	}

	// todo: find a better way for performing file name translation inside
	// a custom config file (this is quite horrible -- part 2)
	if customConfigIndex >= 0 {
		originalFile := opts.files[customConfigIndex]
		content, err := originalFile.Content()
		if err != nil {
			return err
		}
		for name, tmpName := range tmpFilesMap {
			content = ([]byte)(strings.ReplaceAll(string(content), name, tmpName))
		}

		editedFile := utils.NewBytesFileAccessor("edited-config.yaml", content)
		opts.files[customConfigIndex] = editedFile
		tempFileName, removeTmpFile, err := e.writeToTempFile(editedFile)
		if err != nil {
			return err
		}
		defer removeTmpFile()
		opts.args[customConfigArgIndex] = tempFileName
	}

	// launch Falco process
	cmdLine := strings.Join(append([]string{e.executable}, opts.args...), " ")
	logrus.WithField("cmd", cmdLine).Debugf("executing falco command")
	cmd := exec.CommandContext(ctx, e.executable, opts.args...)
	cmd.Stdout = opts.stdout
	cmd.Stderr = opts.stderr
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
		err = &ExitCodeError{Code: exitErr.ExitCode()}
	}
	return err
}
