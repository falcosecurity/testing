package falcoctl

import (
	"os"
	"strings"

	"github.com/falcosecurity/testing/pkg/run"
)

// WithArgs runs falcoctl with the given arguments.
func WithArgs(args ...string) TestOption {
	return func(ro *testOptions) { ro.args = append(ro.args, args...) }
}

// WithConfig runs falcoctl with the given config file through the `--config` option.
func WithConfig(config run.FileAccessor) TestOption {
	return func(ro *testOptions) {
		ro.args = removeFromArgs(ro.args, "--config", 1)
		ro.args = append(ro.args, "--config="+config.Name())
		ro.files = append(ro.files, config)
	}
}

// WithPluginsDir runs falcoctl with the given custom plugins dir file through the `--plugins-dir` option.
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

// WithRulesFilesDir runs falcoctl with the given custom rules files dir file through the `--rulesfiles-dir` option.
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
