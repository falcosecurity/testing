// NOTE: this file is a 1-1 porting of the legacy regression tests
// implemented in python that we historically have in falcosecurity/falco
// (see: https://github.com/falcosecurity/falco/tree/059a28184d1d4f498f5b0bd53ffe10d6fedf35c2/test).
// The porting has been 90% automated with a migration script
// (see: https://github.com/jasondellaluce/falco-testing/blob/32ce0c31eb8fa098a689f1888a4f11b984ae26d8/migration/main.go).
//
// Data files used for running the tests is generated on-the-fly by using
// `go generate` and are pulled from the same sources used in the python tests.
// Those files include rules, configurations, and captures files downloaded from
// both download.falco.org and the checked-in falcosecurity/falco source code.
//
// These tests only implements the legacy tests on the Falco executable, namely:
// - falco_tests.yaml
// - falco_traces.yaml
// - falco_tests_exceptions.yaml
//

package testfalco

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/tests"
	"github.com/jasondellaluce/falco-testing/tests/data/captures"
	"github.com/jasondellaluce/falco-testing/tests/data/configs"
	"github.com/jasondellaluce/falco-testing/tests/data/rules"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFalco_Legacy_EngineVersionMismatch(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.EngineVersionMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("required_engine_version"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_MacroOverriding(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRule, rules.OverrideMacro),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_Endswith(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.Endswith),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DisabledAndEnabledRules1(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRule),
		falco.WithDisabledTags("a"),
		falco.WithEnabledTags("a"),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.Regexp(t, `Runtime error: You can not specify both disabled .-D/-T. and enabled .-t. rules. Exiting.`, res.Stderr())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_StdoutOutputStrict(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.StdoutOutput),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "time_format_iso_8601=true"),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_StdoutOutputJsonStrict(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.StdoutOutput),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRuleWithTags),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "time_format_iso_8601=true"),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListAppendFalse(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.ListAppendFalse),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MacroAppend(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.MacroAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListSubstring(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.ListSubstring),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidNotArray(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidNotArray),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("rules content").
		ForMessage("Rules content is not yaml array of objects"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidEngineVersionNotNumber(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidEngineVersionNotNumber),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("required_engine_version").
		ForMessage("Can't decode YAML scalar value"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidOverwriteRuleMultipleDocs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidOverwriteRuleMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("rule").
		ForItemName("some rule").
		ForMessage("Undefined macro 'bar' used in filter."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledRulesUsingSubstring(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.EmptyRules, rules.SingleRule),
		falco.WithDisabledRules("open_from"),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DetectSkipUnknownNoevt(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SkipUnknownEvt),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListAppend(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleAppendSkipped(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithMinRulePriority("ERROR"),
		falco.WithRules(rules.SingleRule, rules.AppendSingleRule),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_SkipUnknownError(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.SkipUnknownError),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_CONDITION").
		ForItemType("rule").
		ForItemName("Contains Unknown Event And Not Skipping").
		ForMessage("filter_check called with nonexistent field proc.nobody"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_MultipleRulesOverriding(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRule, rules.OverrideRule),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidAppendMacro(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidBaseMacro, rules.InvalidAppendMacro),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_CONDITION").
		ForItemType("macro").
		ForItemName("some macro").
		ForMessage("unexpected token after 'execve', expecting 'or', 'and'"))
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		ForCode("LOAD_UNUSED_MACRO").
		ForItemType("macro").
		ForItemName("some macro").
		ForMessage("Macro not referred to by any other rule/macro"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidMissingListName(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidMissingListName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("list").
		ForMessage("Mapping for key 'list' is empty"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledTagsB(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithDisabledTags("b"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunTagsC(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("c"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunTagsAbc(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("a", "b", "c"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleAppend(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListOverriding(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRule, rules.OverrideList),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListSubBare(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListSubBare),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidAppendMacroDangling(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidAppendMacroDangling),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("macro").
		ForItemName("dangling append").
		ForMessage("Macro has 'append' key but no macro by that name already exists"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidOverwriteMacroMultipleDocs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidOverwriteMacroMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("macro").
		ForItemName("some macro").
		ForMessage("Undefined macro 'foo' used in filter."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledTagsA(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithDisabledTags("a"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidYamlParseError(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidYamlParseError),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_PARSE").
		ForItemType("rules content").
		ForMessage("yaml-cpp: error at line 1, column 11: illegal map value"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidRuleWithoutOutput(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidRuleWithoutOutput),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("rule").
		ForItemName("no output rule").
		ForMessage("Item has no mapping for key 'output'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_Syscalls(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.Syscalls),
		falco.WithCaptureFile(captures.Syscall),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 2, res.Detections().ForRule("detect_madvise").Count())
	assert.Equal(t, 2, res.Detections().ForRule("detect_open").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_BuiltinRulesNoWarnings(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithCaptureFile(captures.Empty),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunTagsA(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("a"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsNone(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsNone),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsIgnore(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsIgnore),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsThresholdOor(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsThresholdOor),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `syscall event drops threshold must be a double in the range`, res.Stderr())
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_MultipleRulesSuppressInfo(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithMinRulePriority("WARNING"),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule, rules.DoubleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 8, res.Detections().ForRule("open_from_cat").Count())
	assert.Equal(t, 1, res.Detections().ForRule("exec_from_cat").Count())
	assert.Equal(t, 0, res.Detections().ForRule("access_from_cat").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListSubMid(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListSubMid),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidListWithoutItems(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidListWithoutItems),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("list").
		ForItemName("bad_list").
		ForMessage("Item has no mapping for key 'items'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledRulesUsingEnabledFlag(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRuleEnabledFlag),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DisabledRuleUsingFalseEnabledFlagOnly(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.DisabledRuleUsingEnabledFlagOnly),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidRuleOutput(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidRuleOutput),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_OUTPUT").
		ForItemType("rule").
		ForItemName("rule_with_invalid_output").
		ForMessage("invalid formatting token not_a_real_field"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_FileOutputStrict(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.FileOutput),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "time_format_iso_8601=true"),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunTagsBc(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("b", "c"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsIgnoreAndLog(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsIgnoreLog),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `syscall event drop action "log" does not make sense with the "ignore" action`, res.Stderr())
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsThresholdNeg(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsThresholdNeg),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `syscall event drops threshold must be a double in the range`, res.Stderr())
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_MultipleRulesLastEmpty(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule, rules.EmptyRules),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListSubWhitespace(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListSubWhitespace),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidMacroWithoutCondition(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidMacroWithoutCondition),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("macro").
		ForItemName("bad_macro").
		ForMessage("Item has no mapping for key 'condition'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_CatchallOrder(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.CatchallOrder),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_dev_null").Count())
	assert.Equal(t, 6, res.Detections().ForRule("dev_null").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListSubFront(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListSubFront),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListOrder(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListOrder),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidMissingMacroName(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidMissingMacroName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("macro").
		ForMessage("Mapping for key 'macro' is empty"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledTagsAbc(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithDisabledTags("a", "b", "c"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_SkipUnknownPrefix(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SkipUnknownPrefix),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsLog(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsLog),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 9`, res.Stderr())
	assert.Regexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidRuleAppendDangling(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.RuleAppendFailure),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("rule").
		ForItemName("my_rule").
		ForMessage("Rule has 'append' key but no rule by that name already exists"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidOverwriteRule(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidBaseRule, rules.InvalidOverwriteRule),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("rule").
		ForItemName("some rule").
		ForMessage("Undefined macro 'bar' used in filter."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledTagsC(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithDisabledTags("c"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunTagsD(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("d"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MacroAppendFalse(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.MacroAppendFalse),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidAppendMacroMultipleDocs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidAppendMacroMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_CONDITION").
		ForItemType("macro").
		ForItemName("some macro").
		ForMessage("unexpected token after 'execve', expecting 'or', 'and'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledRules(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.EmptyRules, rules.SingleRule),
		falco.WithDisabledRules("open_from_cat"),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MultipleRules(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule, rules.DoubleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MultipleDocs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule, rules.DoubleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_NestedListOverriding(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRule, rules.OverrideNestedList),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MacroOrder(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.MacroOrder),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidAppendRuleWithoutCondition(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidAppendRuleWithoutCondition),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("rule").
		ForItemName("no condition rule").
		ForMessage("Appended rule must have exceptions or condition property"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_SkipUnknownUnspecError(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.SkipUnknownUnspec),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_CONDITION").
		ForItemType("rule").
		ForItemName("Contains Unknown Event And Unspecified").
		ForMessage("filter_check called with nonexistent field proc.nobody"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsAlert(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsAlert),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.Regexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MonitorSyscallDropsExit(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.DropsExit),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 1 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 1`, res.Stderr())
	assert.Regexp(t, `Falco internal: syscall event drop`, res.Stderr())
	assert.Regexp(t, `Exiting.`, res.Stderr())
	assert.NotRegexp(t, `Falco internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledTagsAb(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithDisabledTags("a", "b"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunTagsB(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("b"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleAppendFalse(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.RuleAppendFalse),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleOrder(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleOrder),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidNotYaml(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidNotYaml),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("rules content").
		ForMessage("Rules content is not yaml"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidOverwriteMacro(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidBaseMacro, rules.InvalidOverwriteMacro),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("macro").
		ForItemName("some macro").
		ForMessage("Undefined macro 'foo' used in filter."))
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		ForCode("LOAD_UNUSED_MACRO").
		ForItemType("macro").
		ForItemName("some macro").
		ForMessage("Macro not referred to by any other rule/macro"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidMissingRuleName(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidMissingRuleName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("rule").
		ForMessage("Mapping for key 'rule' is empty"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleNamesWithSpaces(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleNamesWithSpaces),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MultipleRulesFirstEmpty(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.EmptyRules, rules.SingleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ProgramOutputStrict(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithConfig(configs.ProgramOutput),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "time_format_iso_8601=true"),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidAppendRule(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidBaseRule, rules.InvalidAppendRule),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_CONDITION").
		ForItemType("rule").
		ForItemName("some rule").
		ForMessage("unexpected token after 'open', expecting 'or', 'and'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidAppendRuleMultipleDocs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidAppendRuleMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_COMPILE_CONDITION").
		ForItemType("rule").
		ForItemName("some rule").
		ForMessage("unexpected token after 'open', expecting 'or', 'and'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_DisabledAndEnabledRules2(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.SingleRule),
		falco.WithDisabledRules("open.*"),
		falco.WithEnabledTags("a"),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.Regexp(t, `Runtime error: You can not specify both disabled .-D/-T. and enabled .-t. rules. Exiting.`, res.Stderr())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RunTagsAb(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.TaggedRules),
		falco.WithEnabledTags("a", "b"),
		falco.WithCaptureFile(captures.OpenMultipleFiles),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().ForRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().ForRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ValidateSkipUnknownNoevt(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.SkipUnknownEvt),
	)
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		ForCode("LOAD_UNKNOWN_FIELD").
		ForItemType("rule").
		ForItemName("Contains Unknown Event And Skipping").
		ForMessage("filter_check called with nonexistent field proc.nobody"))
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ListSubEnd(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ListSubEnd),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InvalidArrayItemNotObject(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.InvalidArrayItemNotObject),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("rules content item").
		ForMessage("Unexpected element type. Each element should be a yaml associative array."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_InvalidListAppendDangling(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ListAppendFailure),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("list").
		ForItemName("my_list").
		ForMessage("List has 'append' key but no list by that name already exists"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionSecondItem(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionSecondItem),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendMultipleValues(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionAppendMultiple),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendComp(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionAppendComp),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionSingleField(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionSingleField),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionNewAppendNoField(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsRuleExceptionNewNoFieldAppend),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("proc_cmdline").
		ForMessage("Rule exception must have fields property with a list of fields"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendOneValue(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionAppendOneValue),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionQuoted(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionQuoted),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendThirdItem(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionAppendThirdItem),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionSingleFieldAppend(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionSingleFieldAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionNewSingleFieldAppend(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionNewSingleFieldAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionUnknownFields(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsItemUnknownFields),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("ex1").
		ForMessage("'not.exist' is not a supported filter field"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionSecondValue(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionSecondValue),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionValuesList(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionValuesList),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendFieldsValuesLenMismatch(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsAppendItemFieldsValuesLenMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("ex1").
		ForMessage("Fields and values lists must have equal length"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendItemNotInRule(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsAppendItemNotInRule),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("ex2").
		ForMessage("Rule exception must have fields property with a list of fields"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionThirdItem(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionThirdItem),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionNoFields(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsItemNoFields),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("exception").
		ForItemName("ex1").
		ForMessage("Item has no mapping for key 'fields'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendNoName(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsAppendItemNoName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("exception").
		ForMessage("Item has no mapping for key 'name'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionCompsFieldsLenMismatch(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsItemCompsFieldsLenMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("ex1").
		ForMessage("Fields and comps lists must have equal length"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionNoValues(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionNoValues),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendSecondValue(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionAppendSecondValue),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionNoName(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsItemNoName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_YAML_VALIDATE").
		ForItemType("exception").
		ForMessage("Item has no mapping for key 'name'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionComp(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionComp),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionValuesListref(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionValuesListref),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionNewSecondFieldAppend(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionNewSecondFieldAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionUnknownComp(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsItemUnknownComp),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("ex1").
		ForMessage("'no-comp' is not a supported comparison operator"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionFieldsValuesLenMismatch(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.ExceptionsItemFieldsValuesLenMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		ForCode("LOAD_ERR_VALIDATE").
		ForItemType("exception").
		ForItemName("ex1").
		ForMessage("Fields and values lists must have equal length"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionOneValue(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionOneValue),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionAppendSecondItem(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionAppendSecondItem),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleExceptionValuesListrefNoparens(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.ExceptionsRuleExceptionValuesListrefNoparens),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ReadSensitiveFileUntrusted(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Read sensitive file untrusted").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_KernelUpgrade(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeKernelUpgrade),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_CreateFilesBelowDev(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveCreateFilesBelowDev),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create files below dev").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ReadSensitiveFileAfterStartup(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveReadSensitiveFileAfterStartup),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Read sensitive file untrusted").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Read sensitive file trusted after startup").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RunShellUntrusted(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveRunShellUntrusted),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("DEBUG").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Run shell untrusted").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ChangeThreadNamespace(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveChangeThreadNamespace),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 0, res.Detections().ForRule("Change thread namespace").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_MkdirBinaryDirs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveMkdirBinaryDirs),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Mkdir binary dirs").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_SystemBinariesNetworkActivity(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveSystemBinariesNetworkActivity),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("System procs network activity").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_WriteRpmDatabase(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveWriteRpmDatabase),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below rpm database").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DockerCompose(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeDockerCompose),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 2, res.Detections().ForRule("Redirect STDOUT/STDIN to Network Connection in Container").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_CurlUninstall(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeCurlUninstall),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DhcpclientRenew(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeDhcpclientRenew),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_StagingWorker(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeStagingWorker),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DbProgramSpawnedProcess(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveDbProgramSpawnedProcess),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("DB program spawned process").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_UserMgmtBinaries(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveUserMgmtBinaries),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("User mgmt binaries").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_Exim4(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeExim4),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_WriteEtc(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveWriteEtc),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below etc").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_StagingCollector(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeStagingCollector),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ContainerPrivileged(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveContainerPrivileged),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 3, res.Detections().ForRule("Launch Privileged Container").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ContainerSensitiveMount(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveContainerSensitiveMount),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 3, res.Detections().ForRule("Launch Sensitive Mount Container").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_WriteBinaryDir(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveWriteBinaryDir),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 4, res.Detections().ForRule("Write below binary dir").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_CurlInstall(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeCurlInstall),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_StagingDb(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeStagingDb),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_ModifyBinaryDirs(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveModifyBinaryDirs),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Modify binary dirs").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_NonSudoSetuid(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveNonSudoSetuid),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Non sudo setuid").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_GitPush(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeGitPush),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_KubeDemo(t *testing.T) {
	// todo(jasondellaluce): this is very heavy and slow, let's skip it for now
	t.Skip()
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithMaxDuration(90*time.Second),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesNegativeKubeDemo),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_FalcoEventGenerator(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveFalcoEventGenerator),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.NotZero(t, res.Detections().ForPriority("DEBUG").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below binary dir").Count())
	assert.Equal(t, 3, res.Detections().ForRule("Read sensitive file untrusted").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Run shell untrusted").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below rpm database").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below etc").Count())
	assert.Equal(t, 1, res.Detections().ForRule("System procs network activity").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Mkdir binary dirs").Count())
	assert.Equal(t, 0, res.Detections().ForRule("System user interactive").Count())
	assert.Equal(t, 1, res.Detections().ForRule("DB program spawned process").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Non sudo setuid").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create files below dev").Count())
	assert.Equal(t, 2, res.Detections().ForRule("Modify binary dirs").Count())
	assert.Equal(t, 0, res.Detections().ForRule("Change thread namespace").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_SystemUserInteractive(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveSystemUserInteractive),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("System user interactive").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_DetectCounts(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithCaptureFile(captures.TracesPositiveFalcoEventGenerator),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below binary dir").Count())
	assert.Equal(t, 3, res.Detections().ForRule("Read sensitive file untrusted").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Run shell untrusted").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below rpm database").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Write below etc").Count())
	assert.Equal(t, 1, res.Detections().ForRule("System procs network activity").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Mkdir binary dirs").Count())
	assert.Equal(t, 0, res.Detections().ForRule("System user interactive").Count())
	assert.Equal(t, 1, res.Detections().ForRule("DB program spawned process").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Non sudo setuid").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create files below dev").Count())
	assert.Equal(t, 2, res.Detections().ForRule("Modify binary dirs").Count())
	assert.Equal(t, 0, res.Detections().ForRule("Change thread namespace").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RuleNamesWithRegexChars(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleNamesWithRegexChars),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 8, res.Detections().ForRule(`Open From Cat ($\.*+?()[]{}|^)`).Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_JsonOutputNoOutputProperty(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotRegexp(t, `.*Warning An open of /dev/null was seen.*`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_JsonOutputNoTagsProperty(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotRegexp(t, `.*"tags":[ ]*\[.*\],.*`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_JsonOutputEmptyTagsProperty(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RuleAppend),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=true"),
	)
	assert.Regexp(t, `.*"tags":[ ]*\[\],.*`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_RulesDirectory(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.RulesDir000SingleRule, rules.RulesDir001DoubleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithAllEvents(),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.NotZero(t, res.Detections().ForPriority("ERROR").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_EnabledRuleUsingFalseEnabledFlagOnly(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.EnabledRuleUsingEnabledFlagOnly),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.Equal(t, 8, res.Detections().ForRule("open_from_cat").Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_NullOutputField(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.NullOutputField),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "json_include_output_property=true"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Regexp(t, `Warning An open was seen .cport=<NA> command=cat /dev/null.`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_InOperatorNetmasks(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.DetectConnectUsingIn),
		falco.WithCaptureFile(captures.ConnectLocalhost),
		falco.WithArgs("-o", "json_include_output_property=false"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_TimeIso8601(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(rules.SingleRule),
		falco.WithCaptureFile(captures.CatWrite),
		falco.WithArgs("-o", "time_format_iso_8601=true"),
		falco.WithArgs("-o", "json_include_output_property=true"),
		falco.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Regexp(t, `^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\+0000`, res.Stderr())
	assert.Regexp(t, `2016-08-04T16:17:57.882054739\+0000: Warning An open was seen`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_TestWarnings(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.FalcoRulesWarnings),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.True(t, res.RuleValidation().At(0).Successful)
	warnings := res.RuleValidation().AllWarnings().
		ForCode("LOAD_NO_EVTTYPE").
		ForItemType("rule").
		ForMessage("Rule matches too many evt.type values. This has a significant performance penalty.")
	assert.NotNil(t, warnings.ForItemName("no_evttype"))
	assert.NotNil(t, warnings.ForItemName("evttype_not_equals"))
	assert.NotNil(t, warnings.ForItemName("leading_not"))
	assert.NotNil(t, warnings.ForItemName("not_equals_at_end"))
	assert.NotNil(t, warnings.ForItemName("not_at_end"))
	assert.NotNil(t, warnings.ForItemName("not_equals_and_not"))
	assert.NotNil(t, warnings.ForItemName("leading_in_not_equals_at_evttype"))
	assert.NotNil(t, warnings.ForItemName("not_with_evttypes"))
	assert.NotNil(t, warnings.ForItemName("not_with_evttypes_addl"))
}

func grpcOutputResponseToFalcoAlert(res *outputs.Response) *falco.Alert {
	outputFields := make(map[string]interface{})
	for k, v := range res.OutputFields {
		outputFields[k] = v
	}
	return &falco.Alert{
		Time:         res.Time.AsTime(),
		Rule:         res.Rule,
		Output:       res.Output,
		Priority:     res.Priority.String(),
		Source:       res.Source,
		Hostname:     res.Hostname,
		Tags:         res.Tags,
		OutputFields: outputFields,
	}
}

func TestFalco_Legacy_GrpcUnixSocketOutputs(t *testing.T) {
	var wg sync.WaitGroup
	defer wg.Wait()
	t.Parallel()

	// launch falco asynchronously
	runner := tests.NewFalcoExecutableRunner(t)
	socketName := runner.WorkDir() + "/falco.sock"
	wg.Add(1)
	go func() {
		defer wg.Done()
		res := falco.Test(
			runner,
			falco.WithRules(rules.SingleRuleWithTags),
			falco.WithConfig(configs.GrpcUnixSocket),
			falco.WithCaptureFile(captures.CatWrite),
			falco.WithMaxDuration(5*time.Second),
			falco.WithArgs("-o", "time_format_iso_8601=true"),
			falco.WithArgs("-o", "grpc.bind_address=unix://"+socketName),
		)
		require.NotContains(t, res.Stderr(), "Error starting gRPC server")
		// todo: skipping this as it can be flacky (Falco sometimes shutsdown
		// with exit code -1), we need to investigate on that
		// require.Nil(t, res.Err())
	}()

	// wait up until Falco creates the unix socket
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(socketName); err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		break
	}

	// connect using the Falco grpc client and collect detection
	grpcClient, err := client.NewForConfig(
		context.Background(),
		&client.Config{UnixSocketPath: "unix://" + socketName},
	)
	require.Nil(t, err)
	var detections falco.Detections
	err = grpcClient.OutputsWatch(context.Background(), func(res *outputs.Response) error {
		detections = append(detections, grpcOutputResponseToFalcoAlert(res))
		return nil
	}, 100*time.Millisecond)

	// perform checks on the detections
	// todo(jasondellaluce): add deeper checks on the received struct
	require.Nil(t, err)
	assert.NotZero(t, detections.Count())
	assert.NotZero(t, detections.
		ForPriority("WARNING").
		ForRule("open_from_cat").Count())
}

func TestFalco_Legacy_NoPluginsUnknownSource(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.PluginsCloudtrailCreateInstances),
	)
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		ForCode("LOAD_UNKNOWN_SOURCE").
		ForItemType("rule").
		ForItemName("Cloudtrail Create Instance").
		ForMessage("Unknown source aws_cloudtrail, skipping"))
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestFalco_Legacy_NoPluginsUnknownSourceRuleException(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(rules.PluginsCloudtrailCreateInstancesExceptions),
	)
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		ForCode("LOAD_UNKNOWN_SOURCE").
		ForItemType("rule").
		ForItemName("Cloudtrail Create Instance").
		ForMessage("Unknown source aws_cloudtrail, skipping"))
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}
