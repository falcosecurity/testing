package driverloader

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/jasondellaluce/falco-testing/pkg/run"
	"go.uber.org/multierr"
)

var (
	// DockerBinds is the set of Docker binds required by the Falco driver
	// loader when running as a Docker privileged container
	DockerBinds = []string{
		"/dev:/host/dev",
		"/proc:/host/proc:ro",
		"/boot:/host/boot:ro",
		"/lib/modules:/host/lib/modules:ro",
		"/usr:/host/usr:ro",
		"/etc:/host/etc:",
	}
)

const (
	// DefaultExecutable is the default path of the falco
	// driver loader executable
	DefaultExecutable = "/usr/bin/falco-driver-loader"
)

// type testOptions struct {
// 	err  error
// 	args []string
// }

// // TestOutput is the output of a Falco run for testing purposes
// type TestOutput struct {
// 	err    error
// 	opts   *testOptions
// 	stdout bytes.Buffer
// 	stderr bytes.Buffer
// }

// // TestOption is an option for testing Falco
// type TestOption func(*testOptions)

// func Test(runner run.Runner, options ...TestOption) *TestOutput {
// 	res := &TestOutput{
// 		opts: &testOptions{},
// 	}
// 	for _, o := range options {
// 		o(res.opts)
// 	}
// 	if res.opts.err != nil {
// 		return res
// 	}

// 	// enforce logging everything on stdout
// 	res.err = runner.Run(context.Background(),
// 		run.WithArgs(res.opts.args...),
// 		run.WithStdout(&res.stdout),
// 		run.WithStderr(&res.stderr),
// 	)
// 	if res.err != nil {
// 		logrus.WithError(res.err).Warn("error in running falco driver loader with tester")
// 	}
// 	return res
// }

func CheckModule() (bool, error) {
	runner, err := run.NewExecutableRunner("lsmod")
	if err != nil {
		return false, err
	}
	var out bytes.Buffer
	err = runner.Run(context.Background(), run.WithStdout(&out))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "falco") {
			return true, nil
		}
	}
	return false, nil
}

func RemoveModule() error {
	runner, err := run.NewExecutableRunner("rmmod")
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	err = runner.Run(
		context.Background(),
		run.WithArgs("falco"),
		run.WithStderr(&stderr),
	)
	if err != nil {
		if err, ok := err.(*run.ExitCodeError); ok {
			return multierr.Append(err, fmt.Errorf("%s", stderr.String()))
		}
	}
	return err
}
