// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package falco

import (
	"bytes"
	"context"
	"time"

	"github.com/falcosecurity/testing/pkg/run"
	"github.com/sirupsen/logrus"
)

var (
	FalcoConfig                 = DefaultConfigFile
	FalcoContainerPluginLibrary = DefaultPluginPath + "/libcontainer.so"
)

const (
	// DefaultMaxDuration is the default max duration of a Falco run
	DefaultMaxDuration = time.Minute * 5
	//
	// DefaultExecutable is the default path of the Falco executable
	DefaultExecutable = "/usr/bin/falco"
	//
	// DefaultConfigFile is the default path of the Falco config file
	DefaultConfigFile = "/etc/falco/falco.yaml"
	//
	// DefaultPluginPath is the default path to the Falco plugins
	DefaultPluginPath = "/usr/share/falco/plugins"
)

type testOptions struct {
	err      error
	args     []string
	files    []run.FileAccessor
	runOpts  []run.RunnerOption
	duration time.Duration
	ctx      context.Context
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
			ctx:      context.Background(),
		},
	}

	// enforce Falco config path as default
	res.opts.args = append(res.opts.args, "-c", FalcoConfig)

	// avoids that the container plugin appends its suggested fields
	// to the rules formatting; in some cases, that can make some tests fail
	// because expected output format would not match with provided string.
	// For example: TestFalco_Legacy_ValidateSkipUnknownNoevt and TestFalco_Legacy_InvalidRuleOutput.
	res.opts.args = append(res.opts.args, "-o", "append_output.suggested_output=false")

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
	ctx, cancel := context.WithTimeout(res.opts.ctx, skewedDuration(res.opts.duration))
	defer cancel()
	res.err = runner.Run(ctx,
		append([]run.RunnerOption{
			run.WithArgs(res.opts.args...),
			run.WithFiles(res.opts.files...),
			run.WithStdout(&res.stdout),
			run.WithStderr(&res.stderr),
		}, res.opts.runOpts...)...,
	)
	if res.err != nil {
		logrus.WithError(res.err).Warn("error running falco with runner")
	}
	return res
}
