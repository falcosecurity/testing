package falco

import (
	"bytes"
	"context"
	"time"

	"github.com/falcosecurity/testing/pkg/run"
	"github.com/sirupsen/logrus"
)

var (
	// PrivilegedDockerBinds is the set of Docker binds required by Falco
	// when running as a Docker privileged container
	PrivilegedDockerBinds = []string{
		"/dev:/host/dev",
		"/proc:/host/proc:ro",
		"/var/run/docker.sock:/host/var/run/docker.sock",
	}
)

const (
	// DefaultMaxDuration is the default max duration of a Falco run
	DefaultMaxDuration = time.Second * 30
	//
	// DefaultFalcoExecutable is the default path of the Falco executable
	DefaultExecutable = "/usr/bin/falco"
)

type testOptions struct {
	err      error
	args     []string
	files    []run.FileAccessor
	duration time.Duration
}

// TestOutput is the output of a Falco test run
type TestOutput struct {
	opts   *testOptions
	err    error
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// TestOption is an option for testing Falco
type TestOption func(*testOptions)

// Test runs a Falco runner with the given test options, and produces
// an output representing the outcome of the run.
func Test(runner run.Runner, options ...TestOption) *TestOutput {
	res := &TestOutput{
		opts: &testOptions{
			duration: DefaultMaxDuration,
		},
	}
	for _, o := range options {
		o(res.opts)
	}
	if res.opts.err != nil {
		return res
	}

	// enforce logging everything on stdout
	res.opts.args = append(res.opts.args, "-o", "log_level=debug")
	res.opts.args = append(res.opts.args, "-o", "log_stderr=true")
	res.opts.args = append(res.opts.args, "-o", "log_syslog=false")
	res.opts.args = append(res.opts.args, "-o", "stdout_output.enabled=true")
	logrus.WithField("deadline", res.opts.duration).Info("running falco with runner")
	ctx, cancel := context.WithTimeout(context.Background(), skewedDuration(res.opts.duration))
	defer cancel()
	res.err = runner.Run(ctx,
		run.WithArgs(res.opts.args...),
		run.WithFiles(res.opts.files...),
		run.WithStdout(&res.stdout),
		run.WithStderr(&res.stderr),
	)
	if res.err != nil {
		logrus.WithError(res.err).Warn("error running falco with runner")
	}
	return res
}
