package falco

import (
	"fmt"
	"time"

	"github.com/jasondellaluce/falco-testing/pkg/run"
)

func withMultipleArgValues(arg string, values ...string) TestOption {
	return func(o *testOptions) {
		for _, v := range values {
			o.args = append(o.args, arg)
			o.args = append(o.args, v)
		}
	}
}

func WithArgs(args ...string) TestOption {
	return func(ro *testOptions) { ro.args = append(ro.args, args...) }
}

func WithRules(rules ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-r", r.Name())
			o.files = append(o.files, r)
		}
	}
}

func WithConfig(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-c", 1)
		o.args = append(o.args, "-c", f.Name())
		o.files = append(o.files, f)
	}
}

func WithEnabledTags(tags ...string) TestOption {
	return withMultipleArgValues("-t", tags...)
}

func WithDisabledTags(tags ...string) TestOption {
	return withMultipleArgValues("-T", tags...)
}

func WithDisabledRules(rules ...string) TestOption {
	return withMultipleArgValues("-D", rules...)
}

func WithEnabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--enable-source", sources...)
}

func WithDisabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--disable-source", sources...)
}

func WithMinRulePriority(priority string) TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "priority="+priority)
	}
}

func WithOutputJSON() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "json_output=true")
	}
}

func WithAllEvents() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-A")
	}
}

func WithCaptureFile(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-e", 1)
		o.args = append(o.args, "-e", f.Name())
		o.files = append(o.files, f)
	}
}

func WithMaxDuration(duration time.Duration) TestOption {
	return func(o *testOptions) {
		o.duration = duration
		o.args = removeFromArgs(o.args, "-M", 1)
		o.args = append(o.args, "-M", fmt.Sprintf("%d", int64(duration.Seconds())))
	}
}

func WithRulesValidation(rules ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-V", r.Name())
			o.files = append(o.files, r)
		}
	}
}

func WithExtraFiles(files ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.files = append(o.files, files...)
	}
}
