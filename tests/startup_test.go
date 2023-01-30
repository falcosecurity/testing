package tests

import (
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/tests/data/configs"
	"github.com/stretchr/testify/assert"
)

func TestStartupFail(t *testing.T) {
	runner := newExecutableRunner(t)
	t.Run("empty-config", func(t *testing.T) {
		res := falco.Test(runner, falco.WithConfig(configs.EmptyConfig))
		assert.NotNil(t, res.Err())
		assert.Equal(t, res.ExitCode(), 1)
		assert.Contains(t, res.Stderr(), "You must specify at least one rules file")
	})
}
