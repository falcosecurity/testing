package falcoctl

import (
	"context"

	"github.com/jasondellaluce/falco-testing/pkg/run"
	"go.uber.org/multierr"
)

func (t *TestOutput) Err() error {
	return multierr.Append(t.opts.err, t.err)
}

func (t *TestOutput) DurationExceeded() bool {
	for _, err := range multierr.Errors(t.Err()) {
		if err == context.DeadlineExceeded {
			return true
		}
	}
	return false
}

func (t *TestOutput) ExitCode() int {
	for _, err := range multierr.Errors(t.Err()) {
		if exitCodeErr, ok := err.(*run.ExitCodeError); ok {
			return exitCodeErr.Code
		}
	}
	return 0
}

func (t *TestOutput) Stdout() string {
	return t.stdout.String()
}

func (t *TestOutput) Stderr() string {
	return t.stderr.String()
}
