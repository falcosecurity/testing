package falcoctl

import (
	"os"
	"strings"

	"github.com/jasondellaluce/falco-testing/pkg/run"
)

func WithArgs(args ...string) TestOption {
	return func(ro *testOptions) { ro.args = append(ro.args, args...) }
}

func WithConfig(config run.FileAccessor) TestOption {
	return func(ro *testOptions) {
		ro.args = removeFromArgs(ro.args, "--config", 1)
		ro.args = append(ro.args, "--config="+config.Name())
		ro.files = append(ro.files, config)
	}
}

func WithPluginsDir(dir string) TestOption {
	return func(ro *testOptions) {
		for i := 0; i < len(ro.args)-1; i++ {
			if ro.args[i] == "artifact" && ro.args[i+1] == "install" {
				os.MkdirAll(dir, os.ModePerm)
				ro.args = removeFromArgs(ro.args, "--plugins-dir", 1)
				ro.args = append(ro.args, "--plugins-dir="+dir)
			}
		}
	}
}

func WithRulesFilesDir(dir string) TestOption {
	return func(ro *testOptions) {
		for i := 0; i < len(ro.args)-1; i++ {
			if ro.args[i] == "artifact" && ro.args[i+1] == "install" {
				os.MkdirAll(dir, os.ModePerm)
				ro.args = removeFromArgs(ro.args, "--rulesfiles-dir", 1)
				ro.args = append(ro.args, "--rulesfiles-dir="+dir)
			}
		}
	}
}

func removeFromArgs(args []string, arg string, nparams int) []string {
	var res []string
	for i := 0; i < len(args); i++ {
		if args[i] == arg || strings.HasPrefix(args[i], arg+"=") {
			i += nparams
		} else {
			res = append(res, args[i])
		}
	}
	return res
}
