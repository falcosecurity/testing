package tests

import (
	"testing"

	"github.com/falcosecurity/falco/regression-tests/pkg/falco"
	"github.com/falcosecurity/falco/regression-tests/tests/data/configs"
	"github.com/stretchr/testify/assert"
)

func TestStartupFail(t *testing.T) {
	runner := falco.NewExecutableRunner(FalcoExecutable)

	t.Run("empty-config", func(t *testing.T) {
		res := falco.TestRun(runner, falco.TestWithConfig(configs.EmptyConfig))
		assert.NotNil(t, res.Err())
		assert.Equal(t, res.ExitCode(), 1)
		assert.Contains(t, res.Stderr(), "You must specify at least one rules file")
	})

}
