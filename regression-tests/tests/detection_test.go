package tests

import (
	"testing"

	"github.com/falcosecurity/falco/regression-tests/pkg/falco"
	"github.com/falcosecurity/falco/regression-tests/tests/data/captures"
	"github.com/falcosecurity/falco/regression-tests/tests/data/rules"
	"github.com/stretchr/testify/assert"
)

func TestDetection(t *testing.T) {
	runner := falco.NewExecutableRunner(FalcoExecutable)

	t.Run("list-append", func(t *testing.T) {
		res := falco.TestRun(runner,
			falco.TestWithOutputJSON(),
			falco.TestWithRules(rules.ListAppend),
			falco.TestWithCaptureFile(captures.CatWrite))
		assert.Nil(t, res.Err())
		assert.Equal(t, 0, res.ExitCode())
		assert.NotZero(t, res.Detections().Count())
		assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	})
}
