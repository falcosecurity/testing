package falcoctl

import (
	"bytes"
	"context"
	"time"

	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultMaxDuration is the default max duration of a falcoctl run
	DefaultMaxDuration = time.Second * 30
	//
	// DefaultExecutable is the default path of the falcoctl executable
	// when installed from a Falco package
	DefaultExecutable = "/usr/bin/falcoctl"
	//
	// DefaultLocalExecutable is the default path of the falcoctl executable
	// when installed manually from a released falcoctl package
	DefaultLocalExecutable = "/usr/local/bin/falcoctl"
)

type testOptions struct {
	workdir  string
	err      error
	args     []string
	duration time.Duration
	files    []run.FileAccessor
}

// TestOutput is the output of a falcoctl run for testing purposes
type TestOutput struct {
	opts   *testOptions
	err    error
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// TestOption is an option for testing falcoctl
type TestOption func(*testOptions)

func Test(runner run.Runner, options ...TestOption) *TestOutput {
	res := &TestOutput{
		opts: &testOptions{
			workdir:  runner.WorkDir(),
			duration: DefaultMaxDuration,
		},
	}
	for _, o := range options {
		o(res.opts)
	}
	if res.opts.err != nil {
		return res
	}

	res.opts.args = removeFromArgs(res.opts.args, "--verbose", 1)
	res.opts.args = removeFromArgs(res.opts.args, "--disable-styling", 1)
	res.opts.args = append(res.opts.args, "--verbose=true", "--disable-styling=true")
	logrus.WithField("deadline", res.opts.duration).Info("running falcoctl with tester")
	ctx, cancel := context.WithTimeout(context.Background(), skewedDuration(res.opts.duration))
	defer cancel()
	res.err = runner.Run(ctx,
		run.WithArgs(res.opts.args...),
		run.WithFiles(res.opts.files...),
		run.WithStdout(&res.stdout),
		run.WithStderr(&res.stderr),
	)
	if res.err != nil {
		logrus.WithError(res.err).Warn("error in running falcoctl with tester")
	}
	return res
}

func skewedDuration(d time.Duration) time.Duration {
	return time.Duration(float64(d) * 1.10)
}
