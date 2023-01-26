package falco

import (
	"bytes"
	"context"
	"time"

	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultMaxDuration is the default max duration of a Falco run
	DefaultMaxDuration = time.Second * 10
)

type testOpts struct {
	err      error
	args     []string
	duration time.Duration
	files    []utils.FileAccessor
}

// TesterOutput is the output of a Falco run for testing purposes
type TesterOutput struct {
	opts   *testOpts
	err    error
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// TesterOption is an option for testing Falco
type TesterOption func(*testOpts)

func TestRun(runner Runner, options ...TesterOption) *TesterOutput {
	res := &TesterOutput{
		opts: &testOpts{
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

	logrus.WithField("maxDuration", res.opts.duration).Info("running falco with tester")
	ctx, cancel := context.WithTimeout(context.Background(), skewedDuration(res.opts.duration))
	defer cancel()
	res.err = runner.Run(ctx,
		RunWithArgs(res.opts.args...),
		RunWithFiles(res.opts.files...),
		RunWithStdout(&res.stdout),
		RunWithStderr(&res.stderr),
	)
	if res.err != nil {
		logrus.WithError(res.err).WithField("stdout", res.Stdout()).Warn("error in running Falco with tester")
	}
	// todo: should we log stderr and stdout? That can become quite messy in the output
	return res
}
