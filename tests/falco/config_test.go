/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package testfalco

import (
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/captures"
	"github.com/falcosecurity/testing/tests/data/configs"
	"github.com/falcosecurity/testing/tests/data/rules"
	"github.com/stretchr/testify/assert"
)

func TestFalco_Config_RuleMatchingFirst(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.ShadowingRules),
		falco.WithConfig(configs.RuleMatchingFirst),
		falco.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		falco.WithOutputJSON(),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.Equal(t, 1, res.Detections().Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
}

func TestFalco_Config_RuleMatchingAll(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.ShadowingRules),
		falco.WithConfig(configs.RuleMatchingAll),
		falco.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		falco.WithOutputJSON(),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.Equal(t, 2, res.Detections().Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
}

func TestFalco_Config_RuleMatchingWrongValue(t *testing.T) {
	t.Parallel()
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(rules.ShadowingRules),
		falco.WithConfig(configs.RuleMatchingWrongValue),
		falco.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		falco.WithOutputJSON(),
	)
	assert.NotNil(t, res.Stderr())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Contains(t, res.Stderr(), "Unknown rule matching strategy")
	assert.Equal(t, 1, res.ExitCode())
}
