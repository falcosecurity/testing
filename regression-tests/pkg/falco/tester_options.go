package falco

import (
	"fmt"
	"time"

	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
)

func testWithMultipleArgValues(arg string, values ...string) TesterOption {
	return func(o *testOpts) {
		for _, v := range values {
			o.args = append(o.args, arg)
			o.args = append(o.args, v)
		}
	}
}

func TestWithArgs(args ...string) TesterOption {
	return func(ro *testOpts) { ro.args = append(ro.args, args...) }
}

func TestWithRules(rules ...utils.FileAccessor) TesterOption {
	return func(o *testOpts) {
		for _, r := range rules {
			o.args = append(o.args, "-r", r.Name())
			o.files = append(o.files, r)
		}
	}
}

func TestWithConfig(f utils.FileAccessor) TesterOption {
	return func(o *testOpts) {
		o.args = removeFromArgs(o.args, "-c", 1)
		o.args = append(o.args, "-c", f.Name())
		o.files = append(o.files, f)
	}
}

func TestWithEnabledTags(tags ...string) TesterOption {
	return testWithMultipleArgValues("-t", tags...)
}

func TestWithDisabledTags(tags ...string) TesterOption {
	return testWithMultipleArgValues("-T", tags...)
}

func TestWithDisableRules(rules ...string) TesterOption {
	return testWithMultipleArgValues("-D", rules...)
}

func TestWithEnabledSources(sources ...string) TesterOption {
	return testWithMultipleArgValues("--enable-source", sources...)
}

func TestWithDisabledSources(sources ...string) TesterOption {
	return testWithMultipleArgValues("--disable-source", sources...)
}

func TestWithMinRulePriority(priority string) TesterOption {
	return func(o *testOpts) {
		o.args = append(o.args, "-o", "priority="+priority)
	}
}

func TestWithOutputJSON() TesterOption {
	return func(o *testOpts) {
		o.args = append(o.args, "-o", "json_output=true")
	}
}

func TestWithAllEvents() TesterOption {
	return func(o *testOpts) {
		o.args = append(o.args, "-A")
	}
}

func TestWithCaptureFile(f utils.FileAccessor) TesterOption {
	return func(o *testOpts) {
		o.args = removeFromArgs(o.args, "-e", 1)
		o.args = append(o.args, "-e", f.Name())
		o.files = append(o.files, f)
	}
}

func TestWithMaxDuration(duration time.Duration) TesterOption {
	return func(o *testOpts) {
		o.args = removeFromArgs(o.args, "-M", 1)
		o.args = append(o.args, "-M", fmt.Sprintf("%d", int64(duration.Seconds())))
	}
}

func TestWithRulesValidation(rules ...utils.FileAccessor) TesterOption {
	return func(o *testOpts) {
		for _, r := range rules {
			o.args = append(o.args, "-V", r.Name())
			o.files = append(o.files, r)
		}
	}
}
