package run

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

type execRunner struct {
	m          sync.Mutex
	executable string
	workDir    string
}

// NewExecutableRunner returns a runner that runs a local executable binary
func NewExecutableRunner(executable string) (Runner, error) {
	if info, err := os.Stat(executable); err != nil || info.IsDir() {
		if info.IsDir() {
			err = fmt.Errorf("file is not an executable")
		}
		return nil, fmt.Errorf("can't access executable '%s': %s", executable, err.Error())
	}
	dir, err := os.MkdirTemp("", execRunnerWorkDirPrefix)
	if err != nil {
		return nil, err
	}
	return &execRunner{
		executable: executable,
		workDir:    dir,
	}, nil
}

func (e *execRunner) WorkDir() string {
	// note: this is constant after construction and does not need
	// mutex protection
	return e.workDir
}

func (e *execRunner) Run(ctx context.Context, options ...RunnerOption) error {
	e.m.Lock()
	defer e.m.Unlock()
	opts := buildRunOptions(options...)
	defer os.RemoveAll(e.WorkDir())
	if err := os.MkdirAll(e.WorkDir(), os.ModePerm); err != nil {
		return err
	}

	// make sure all files are accessible
	for _, f := range opts.files {
		// if file's name is a relative path, copy it in the workdir
		if !path.IsAbs(f.Name()) {
			newAbsPath := e.WorkDir() + "/" + f.Name()
			if err := os.MkdirAll(filepath.Dir(newAbsPath), os.ModePerm); err != nil {
				return err
			}
			if local, ok := f.(*localFileAccessor); ok {
				if err := os.Symlink(local.path, newAbsPath); err != nil {
					return err
				}
			} else {
				content, err := f.Content()
				if err != nil {
					return err
				}
				err = os.WriteFile(newAbsPath, content, os.ModePerm)
				if err != nil {
					return err
				}
			}
		} else {
			if _, ok := f.(*localFileAccessor); !ok {
				return fmt.Errorf("executable runner does not support in-memory files with an absolute path as name")
			}
			// the file's name is an absolute path, so it should be already
			// be accessible as-is without further path mangling
		}
	}

	// launch a process
	cmdLine := strings.Join(append([]string{e.executable}, opts.args...), " ")
	logrus.WithField("cmd", cmdLine).Debugf("executing command")
	cmd := exec.CommandContext(ctx, e.executable, opts.args...)
	cmd.Stdout = opts.stdout
	cmd.Stderr = opts.stderr
	cmd.Dir = e.WorkDir()
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
		err = &ExitCodeError{Code: exitErr.ExitCode()}
	}
	return err
}
