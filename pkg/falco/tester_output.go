package falco

import (
	"context"
	"encoding/json"

	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

func (t *TestOutput) hasOutputJSON() bool {
	for i := 0; i < len(t.opts.args)-1; i++ {
		if t.opts.args[i] == "-o" && t.opts.args[i+1] == "json_output=true" {
			return true
		}
	}
	return false
}

// Err returns a non-nil error in case of issues when running Falco.
func (t *TestOutput) Err() error {
	return multierr.Append(t.opts.err, t.err)
}

// DurationExceeded returns true if the Falco run exceeded the expected
// duration or if the context had expired.
func (t *TestOutput) DurationExceeded() bool {
	for _, err := range multierr.Errors(t.Err()) {
		if err == context.DeadlineExceeded {
			return true
		}
	}
	return false
}

// ExitCode returns the numeric exit code of the Falco process.
func (t *TestOutput) ExitCode() int {
	for _, err := range multierr.Errors(t.Err()) {
		if exitCodeErr, ok := err.(*run.ExitCodeError); ok {
			return exitCodeErr.Code
		}
	}
	return 0
}

// Stdout returns a string containing the stdout output of the Falco run.
func (t *TestOutput) Stdout() string {
	return t.stdout.String()
}

// Stderr returns a string containing the stderr output of the Falco run.
func (t *TestOutput) Stderr() string {
	return t.stderr.String()
}

// StdoutJSON deserializes the stdout of the Falco run using the JSON encoding.
// Returns true if the stdout is not encoded as JSON.
func (t *TestOutput) StdoutJSON() map[string]interface{} {
	res := make(map[string]interface{})
	if err := json.Unmarshal([]byte(t.Stdout()), &res); err != nil {
		logrus.Errorf("TestOutput.StdoutJSON: stdout is not json")
		return nil
	}
	return res
}
