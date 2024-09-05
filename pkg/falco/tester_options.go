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
	"context"
	"fmt"
	"time"

	"github.com/falcosecurity/testing/pkg/run"
)

func withMultipleArgValues(arg string, values ...string) TestOption {
	return func(o *testOptions) {
		for _, v := range values {
			o.args = append(o.args, arg)
			o.args = append(o.args, v)
		}
	}
}

// WithArgs runs Falco with the given arguments.
func WithArgs(args ...string) TestOption {
	return func(ro *testOptions) { ro.args = append(ro.args, args...) }
}

// WithRules runs Falco with the given rules files through the `-r` option.
func WithRules(rules ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-r", r.Name())
			o.files = append(o.files, r)
		}
	}
}

// WithConfig runs Falco with the given config file through the `-c` option.
func WithConfig(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-c", 1)
		o.args = append(o.args, "-c", f.Name())
		o.files = append(o.files, f)
	}
}

// WithEnabledTags runs Falco with enabled rules tags through the `-t` option.
func WithEnabledTags(tags ...string) TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "rules[].disable.rule=*")
		for _, t := range tags {
			o.args = append(o.args, "-o", "rules[].enable.tag="+t)
		}
	}
}

// WithDisabledTags runs Falco with disabled rules tags through the `-T` option.
func WithDisabledTags(tags ...string) TestOption {
	return func(o *testOptions) {
		for _, t := range tags {
			o.args = append(o.args, "-o", "rules[].disable.tag="+t)
		}
	}
}

// WithDisabledRules runs Falco with disabled rules through the `rules:` config option.
func WithDisabledRules(rules ...string) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-o", "rules[].disable.rule="+r)
		}
	}
}

// WithEnabledSources runs Falco with enabled event sources through the `--enable-source` option.
func WithEnabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--enable-source", sources...)
}

// WithDisabledSources runs Falco with disabled event sources through the `--disable-source` option.
func WithDisabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--disable-source", sources...)
}

// WithPrometheusMetrics runs Falco enabling prometheus metrics endpoint.
func WithPrometheusMetrics() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "metrics.enabled=true")
		o.args = append(o.args, "-o", "metrics.output_rule=true")
		o.args = append(o.args, "-o", "metrics.interval=2s")
		o.args = append(o.args, "-o", "webserver.enabled=true")
		o.args = append(o.args, "-o", "webserver.prometheus_metrics_enabled=true")
	}
}

// WithMinRulePriority runs Falco by forcing a mimimum rules priority.
func WithMinRulePriority(priority string) TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "priority="+priority)
	}
}

// WithOutputJSON runs Falco by forcing a the output in JSON format.
func WithOutputJSON() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "json_output=true")
	}
}

// WithAllEvents runs Falco with all events enabled through the `-A` option.
func WithAllEvents() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-A")
	}
}

// WithCaptureFile runs Falco reading events from a capture file through the `-o engine.kind=replay` option.
func WithCaptureFile(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "engine.kind=replay", "-o", fmt.Sprintf("engine.replay.capture_file=%s", f.Name()))
		o.files = append(o.files, f)
	}
}

// WithContextDeadline runs Falco with a maximum context deadline.
func WithContextDeadline(duration time.Duration) TestOption {
	return func(o *testOptions) {
		o.duration = duration
	}
}

// WithRulesValidation runs Falco with the given rules files to be validated through the `-V` option.
func WithRulesValidation(rules ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-V", r.Name())
			o.files = append(o.files, r)
		}
	}
}

// WithExtraFiles runs Falco with a given set of extra loaded files.
// This can be used to make the underlying runner aware of files referred to by
// Falco, its config, or arguments set with WithArgs.
func WithExtraFiles(files ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.files = append(o.files, files...)
	}
}

// WithEnvVars runs Falco with a given set of environment varibles.
func WithEnvVars(vars map[string]string) TestOption {
	return func(o *testOptions) {
		o.runOpts = append(o.runOpts, run.WithEnvVars(vars))
	}
}

// WithContext runs Falco with a given context.
func WithContext(ctx context.Context) TestOption {
	return func(o *testOptions) { o.ctx = ctx }
}

// WithStopAfter tells Falco to stop after 'duration' with the `-M` option.
func WithStopAfter(duration time.Duration) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-M", 1)
		o.args = append(o.args, "-M", fmt.Sprintf("%d", int64(duration.Seconds())))
	}
}
