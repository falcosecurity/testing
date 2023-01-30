package falco

import (
	"context"
	"fmt"
	"io"

	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
)

const (
	// DefaultFalcoExecutable is the default path of the Falco executable
	DefaultFalcoExecutable = "/usr/bin/falco"
)

type runOpts struct {
	args   []string
	files  []utils.FileAccessor
	stderr io.Writer
	stdout io.Writer
}

// RunnerOption is an option for running Falco
type RunnerOption func(*runOpts)

// Runner runs Falco with a given set of options
type Runner interface {
	// Run runs Falco with the given options and returns when it finishes its
	// execution or when the context deadline is exceeded.
	// Returns a non-nil error in case of failure.
	Run(ctx context.Context, options ...RunnerOption) error
}

// RunWithFiles is an option for running Falco with some files
// to be used during execution and/or referenced in the CLI args
// (e.g. rules files, config files, capture files, etc...).
// For example, if you run Falco with `-c` (through WithArgs), you
// should add the referenced config file with RunWithFiles.
func RunWithFiles(files ...utils.FileAccessor) RunnerOption {
	return func(ro *runOpts) { ro.files = append(ro.files, files...) }
}

// RunWithArgs is an option for running Falco with a given set of CLI arguments
func RunWithArgs(args ...string) RunnerOption {
	return func(ro *runOpts) { ro.args = append(ro.args, args...) }
}

// WithArgs is an option for running Falco by writing stdout on a given writer
func RunWithStdout(writer io.Writer) RunnerOption {
	return func(ro *runOpts) { ro.stdout = writer }
}

// WithArgs is an option for running Falco by writing stderr on a given writer
func RunWithStderr(writer io.Writer) RunnerOption {
	return func(ro *runOpts) { ro.stderr = writer }
}

// ExitCodeError is an error representing the exit code of Falco
type ExitCodeError struct {
	Code int
}

func (c *ExitCodeError) Error() string {
	return fmt.Sprintf("error code %d", c.Code)
}

func buildRunOptions(opts ...RunnerOption) *runOpts {
	res := &runOpts{
		args:   []string{},
		files:  []utils.FileAccessor{},
		stderr: io.Discard,
		stdout: io.Discard,
	}
	for _, o := range opts {
		o(res)
	}
	return res
}
