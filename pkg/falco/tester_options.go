package falco

import (
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
	return withMultipleArgValues("-t", tags...)
}

// WithDisabledTags runs Falco with disabled rules tags through the `-T` option.
func WithDisabledTags(tags ...string) TestOption {
	return withMultipleArgValues("-T", tags...)
}

// WithDisabledRules runs Falco with disabled rules through the `-D` option.
func WithDisabledRules(rules ...string) TestOption {
	return withMultipleArgValues("-D", rules...)
}

// WithEnabledSources runs Falco with enabled event sources through the `--enable-source` option.
func WithEnabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--enable-source", sources...)
}

// WithDisabledSources runs Falco with disabled event sources through the `--disable-source` option.
func WithDisabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--disable-source", sources...)
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

// WithCaptureFile runs Falco reading events from a capture file through the `-e` option.
func WithCaptureFile(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-e", 1)
		o.args = append(o.args, "-e", f.Name())
		o.files = append(o.files, f)
	}
}

// WithMaxDuration runs Falco with a maximum duration through the `-M` option.
func WithMaxDuration(duration time.Duration) TestOption {
	return func(o *testOptions) {
		o.duration = duration
		o.args = removeFromArgs(o.args, "-M", 1)
		o.args = append(o.args, "-M", fmt.Sprintf("%d", int64(duration.Seconds())))
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
