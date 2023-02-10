package falcoctl

import (
	"context"

	"github.com/falcosecurity/testing/pkg/run"
	"go.uber.org/multierr"
)

// Err returns a non-nil error in case of issues when running falcoctl.
func (t *TestOutput) Err() error {
	return multierr.Append(t.opts.err, t.err)
}

// DurationExceeded returns true if the falcoctl run exceeded the expected
// duration or if the context had expired.
func (t *TestOutput) DurationExceeded() bool {
	for _, err := range multierr.Errors(t.Err()) {
		if err == context.DeadlineExceeded {
			return true
		}
	}
	return false
}

// ExitCode returns the numeric exit code of the falcoctl process.
func (t *TestOutput) ExitCode() int {
	for _, err := range multierr.Errors(t.Err()) {
		if exitCodeErr, ok := err.(*run.ExitCodeError); ok {
			return exitCodeErr.Code
		}
	}
	return 0
}

// Stdout returns a string containing the stdout output of the falcoctl run.
func (t *TestOutput) Stdout() string {
	return t.stdout.String()
}

// Stderr returns a string containing the stderr output of the falcoctl run.
func (t *TestOutput) Stderr() string {
	return t.stderr.String()
}
