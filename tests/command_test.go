package tests

import (
	"regexp"
	"testing"

	"github.com/falcosecurity/falco/regression-tests/pkg/falco"
	"github.com/stretchr/testify/assert"
)

func TestCommandVersion(t *testing.T) {
	runner := falco.NewExecutableRunner(FalcoExecutable)
	t.Run("text-output", func(t *testing.T) {
		res := falco.TestRun(runner, falco.TestWithArgs("--version"))
		assert.Nil(t, res.Err())
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
		res := falco.TestRun(runner,
			falco.TestWithArgs("--version"),
			falco.TestWithOutputJSON(),
		)
		out := res.StdoutJSON()
		assert.Nil(t, res.Err())
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
