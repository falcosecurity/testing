package falco

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
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

	for _, file := range opts.files {
		// create temp file to dump the YAML configuration
		tempFileName, removeTmpFile, err := e.writeToTempFile(file)
		if err != nil {
			return err
		}
		defer removeTmpFile()
		for i := 0; i < len(opts.args); i++ {
			if opts.args[i] == file.Name() {
				opts.args[i] = tempFileName
			}
		}
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
