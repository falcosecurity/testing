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

// NewExecutableRunner returns a Falco runner that runs a local executable binary
func NewExecutableRunner(executable string) (Runner, error) {
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

// contract:
// if a file is a relpath, or is within the work dir, it's moved in the
// workdir
// if file is an absolute path, it is accessed as-is (note: this can have issues
// for docker (let's see, maybe mounting will be enough))

func (e *execRunner) Run(ctx context.Context, options ...RunnerOption) error {
	e.m.Lock()
	defer e.m.Unlock()
	opts := buildRunOptions(options...)
	defer os.RemoveAll(e.WorkDir())
	if err := os.MkdirAll(e.WorkDir(), os.ModePerm); err != nil {
		return err
	}

	// if path is a relative path, or is within workdir:
	// - if is a local file, create a symlink
	// - else write it in workdir with its rel name
	// if path is an absolute path, do nothing
	for _, f := range opts.files {
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
		}
	}

	// launch Falco process
	cmdLine := strings.Join(append([]string{e.executable}, opts.args...), " ")
	logrus.WithField("cmd", cmdLine).Debugf("executing falco command")
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
