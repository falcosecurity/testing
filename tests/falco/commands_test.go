package testfalco

import (
	"regexp"
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/tests"

	"github.com/stretchr/testify/assert"
)

// todo(jasondellaluce): implement tests for the non-covered Falco cmds/args:
// Commands printing information:
//   -h, --help, --support, -i, -L, -l, --list, --list-syscall-events,
//   --markdown, -N, --gvisor-generate-config, --page-size
// Metadata collection and container runtimes:
//   --cri, --disable-cri-async, -k, --k8s-api, -K, --k8s-api-cert, --k8s-node, -m, --mesos-api
// Falco event collection modes:
//   -g, --gvisor-config, --gvisor-root, -u, --userspace, --modern-bpf
// Changers of Falco's behavior:
//   --disable-source, --enable-source, -A, -d, --daemon, -P, --pidfile,
//   -p, --print, -b, --print-base64, -S, --snaplen,
// Misc Falco features:
//   -s, --stats-interval, -U, --unbuffered

func TestCmd_Version(t *testing.T) {
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("text-output", func(t *testing.T) {
		res := falco.Test(runner, falco.WithArgs("--version"))
		assert.Nil(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		assert.Regexp(t, regexp.MustCompile(
			`Falco version:[\s]+[0-9]+\.[0-9]+\.[0-9](\-[0-9]+\+[a-f0-9]+)?[\s]+`+
				`Libs version:[\s]+[0-9]+\.[0-9]+\.[0-9][\s]+`+
				`Plugin API:[\s]+[0-9]+\.[0-9]+\.[0-9][\s]+`+
				`Engine:[\s]+[0-9]+[\s]+`+ // note: since falco 0.34.0
				`Driver:[\s]+`+
				`API version:[\s]+[0-9]+\.[0-9]+\.[0-9][\s]+`+
				`Schema version:[\s]+[0-9]+\.[0-9]+\.[0-9][\s]+`+
				`Default driver:[\s]+[0-9]+\.[0-9]+\.[0-9]\+driver`),
			res.Stdout())
	})
	t.Run("json-output", func(t *testing.T) {
		res := falco.Test(runner,
			falco.WithArgs("--version"),
			falco.WithOutputJSON(),
		)
		out := res.StdoutJSON()
		assert.Nil(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		assert.Contains(t, out, "default_driver_version")
		assert.Contains(t, out, "driver_api_version")
		assert.Contains(t, out, "driver_schema_version")
		assert.Contains(t, out, "engine_version")
		assert.Contains(t, out, "falco_version")
		assert.Contains(t, out, "libs_version")
		assert.Contains(t, out, "plugin_api_version")
	})
}

func TestCmd_ListPlugins(t *testing.T) {
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("--list-plugins"),
		falco.WithArgs("-o", "load_plugins[0]=cloudtrail"),
		falco.WithArgs("-o", "load_plugins[1]=json"),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, res.ExitCode(), 0)
	assert.Regexp(t, regexp.MustCompile(
		`2 Plugins Loaded:[\s]+`+
			`Name: cloudtrail[\s]+`+
			`Description: .*[\s]+`+
			`Contact: .*[\s]+`+
			`Version: .*[\s]+`+
			`Capabilities:[\s]+`+
			`- Event Sourcing \(ID=2, source='aws_cloudtrail'\)[\s]+`+
			`- Field Extraction[\s]+`+
			`Name: json[\s]+`+
			`Description: .*[\s]+`+
			`Contact: .*[\s]+`+
			`Version: .*[\s]+`+
			`Capabilities:[\s]+`+
			`[\s]+`+
			`- Field Extraction`),
		res.Stdout())
}

func TestCmd_PluginInfo(t *testing.T) {
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("--plugin-info=cloudtrail"),
		falco.WithArgs("-o", "load_plugins[0]=cloudtrail"),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, res.ExitCode(), 0)
	assert.Regexp(t, regexp.MustCompile(
		`Name: cloudtrail[\s]+`+
			`Description: .*[\s]+`+
			`Contact: .*[\s]+`+
			`Version: .*[\s]+`+
			`Capabilities:[\s]+`+
			`- Event Sourcing \(ID=2, source='aws_cloudtrail'\)[\s]+`+
			`- Field Extraction[\s]+`+
			`Init config schema type: JSON[\s]+.*[\s]+`+
			`No suggested open params available.*`),
		res.Stdout())
}
