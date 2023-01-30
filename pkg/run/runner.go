package run

import (
	"context"
	"fmt"
	"io"
)

type runOpts struct {
	stderr io.Writer
	stdout io.Writer
	args   []string
	files  []FileAccessor
}

// RunnerOption is an option for running Falco
type RunnerOption func(*runOpts)

// Runner runs Falco with a given set of options
type Runner interface {
	// Run runs Falco with the given options and returns when it finishes its
	// execution or when the context deadline is exceeded.
	// Returns a non-nil error in case of failure.
	Run(ctx context.Context, options ...RunnerOption) error
	// WorkDir return the absolute path to the working directory assigned
	// to the runner.
	WorkDir() string
}

// WithFiles is an option for running Falco with some files
// to be used during execution and/or referenced in the CLI args
// (e.g. rules files, config files, capture files, etc...).
// For example, if you run Falco with `-c` (through WithArgs), you
// should add the referenced config file with WithFiles.
func WithFiles(files ...FileAccessor) RunnerOption {
	return func(ro *runOpts) { ro.files = append(ro.files, files...) }
}

// WithArgs is an option for running Falco with a given set of CLI arguments
func WithArgs(args ...string) RunnerOption {
	return func(ro *runOpts) { ro.args = append(ro.args, args...) }
}

// WithArgs is an option for running Falco by writing stdout on a given writer
func WithStdout(writer io.Writer) RunnerOption {
	return func(ro *runOpts) { ro.stdout = writer }
}

// WithArgs is an option for running Falco by writing stderr on a given writer
func WithStderr(writer io.Writer) RunnerOption {
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
		files:  []FileAccessor{},
		stderr: io.Discard,
		stdout: io.Discard,
	}
	for _, o := range opts {
		o(res)
	}
	return res
}
