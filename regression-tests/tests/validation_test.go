package tests

import (
	"regexp"
	"testing"

	"github.com/falcosecurity/falco/regression-tests/pkg/falco"
	"github.com/falcosecurity/falco/regression-tests/tests/data/rules"
	"github.com/stretchr/testify/assert"
)

func TestValidationFail(t *testing.T) {
	runner := falco.NewExecutableRunner(FalcoExecutable)

	t.Run("invalid-macro-loop", func(t *testing.T) {
		res := falco.TestRun(runner,
			falco.TestWithOutputJSON(),
			falco.TestWithRulesValidation(rules.InvalidMacroLoop))
		assert.NotNil(t, res.Err())
		assert.Equal(t, 1, res.ExitCode())
		assert.False(t, res.RuleValidation().Successful())
		assert.NotNil(t, res.RuleValidation().Errors().
			ForCode("LOAD_ERR_VALIDATE").
			ForItemType("macro").
			ForItemName("macro_a").
			ForMessage(regexp.MustCompile(".*reference loop in macro.*")),
		)
	})

}
