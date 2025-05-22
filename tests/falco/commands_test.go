// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/outputs"
	"github.com/falcosecurity/testing/tests/data/rules"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// todo(jasondellaluce): implement tests for the non-covered Falco cmds/args:
// Commands printing information:
//   -h, --help, --support, -l, --list, --list-syscall-events,
//   --markdown, -N, --gvisor-generate-config, --page-size
// Metadata collection and container runtimes:
//   --cri, --disable-cri-async, -k, --k8s-api, -K, --k8s-api-cert, --k8s-node, -m, --mesos-api
// Changers of Falco's behavior:
//   --disable-source, --enable-source, -A, -d, --daemon, -P, --pidfile,
//   -p, --print, -b, --print-base64, -S, --snaplen,
// Misc Falco features:
//   -s, --stats-interval, -U, --unbuffered

const (
	semVerRegex     string = `((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)`
	commitHashRegex string = `([a-f0-9]+)`
	tagRegex        string = `[0-9]+\.[0-9]+\.[0-9]`
)

func TestFalco_Cmd_Version(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("text-output", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(runner, falco.WithArgs("--version"))
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		// Falco version supports:
		// - (dev) -> 0.36.0-198+30aa28f
		// - (release) -> 0.36.0
		// - (release-rc) -> 0.36.0-rc1
		// Libs version supports:
		// - (commit hash) -> e999e61fa8f57ca8e9590e4c108fd4a12459ec48
		// - (release) -> 0.13.0
		// - (release-rc) -> 0.13.0-rc1
		// Default driver supports:
		// - (commit hash) -> e999e61fa8f57ca8e9590e4c108fd4a12459ec48
		// - (release) -> 6.0.1+driver
		// - (release-rc) -> 6.0.1-rc1+driver
		assert.Regexp(t, regexp.MustCompile(
			`Falco version:[\s]+`+semVerRegex+`[\s]+`+
				`Libs version:[\s]+(`+semVerRegex+`|`+commitHashRegex+`)[\s]+`+
				`Plugin API:[\s]+`+tagRegex+`[\s]+`+
				`Engine:[\s]+`+tagRegex+`[\s]+`+
				`Driver:[\s]+`+
				`API version:[\s]+`+tagRegex+`[\s]+`+
				`Schema version:[\s]+`+tagRegex+`[\s]+`+
				`Default driver:[\s]+(`+semVerRegex+`|`+commitHashRegex+`)[\s]*`),
			res.Stdout())
	})
	t.Run("json-output", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(runner,
			falco.WithArgs("--version"),
			falco.WithOutputJSON(),
		)
		out := res.StdoutJSON()
		assert.NoError(t, res.Err(), "%s", res.Stderr())
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

func TestFalco_Cmd_ListPlugins(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	checkNotStaticExecutable(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("--list-plugins"),
		falco.WithArgs("-o", "load_plugins[0]=cloudtrail"),
		falco.WithArgs("-o", "load_plugins[1]=json"),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
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

func TestFalco_Cmd_PluginInfo(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	checkNotStaticExecutable(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("--plugin-info=cloudtrail"),
		falco.WithArgs("-o", "load_plugins[0]=cloudtrail"),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
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

func TestFalco_Print_IgnoredEvents(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	bytearr, err := outputs.EventData.Content()
	if err != nil {
		panic(err)
	}
	events := strings.Split(string(bytearr), ",")
	runner := tests.NewFalcoExecutableRunner(t)
	res := falco.Test(
		runner,
		falco.WithArgs("-i"),
	)
	assert.Contains(t, res.Stdout(), "Ignored syscall(s)")
	for _, event := range events {
		assert.Contains(t, res.Stdout(), event)
	}
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, res.ExitCode(), 0)
}

func TestFalco_Print_Rules(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	runner := tests.NewFalcoExecutableRunner(t)

	t.Run("invalid-rules", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(
			runner,
			falco.WithArgs("-L"),
			falco.WithRules(rules.InvalidRuleOutput),
		)
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 1)
	})

	t.Run("text-valid-rules", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(
			runner,
			falco.WithArgs("-L"),
			falco.WithRules(rules.DetectConnectUsingIn, rules.ListAppend, rules.CatchallOrder),
		)
		rules := []string{"Open From Cat", "Localhost connect", "open_dev_null", "dev_null"}
		for _, rule := range rules {
			assert.Contains(t, res.Stdout(), rule)
		}
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
	})

	t.Run("json-valid-rules", func(t *testing.T) {
		t.Parallel()
		checkNotStaticExecutable(t)
		res := falco.Test(
			runner,
			falco.WithArgs("-L"),
			falco.WithOutputJSON(),
			falco.WithArgs("-o", "load_plugins[0]=json"),
			falco.WithRules(rules.RulesDir000SingleRule, rules.RulesListWithPluginJSON),
		)

		assert.NoError(t, res.Err())
		infos := res.RulesetDescription()
		assert.NotNil(t, infos)

		// check required engine version
		assert.Equal(t, "0.11.0", infos.RequiredEngineVersion)

		// check required plugin versions
		require.Len(t, infos.RequiredPluginVersions, 1)
		assert.Equal(t, "json", infos.RequiredPluginVersions[0].Name)
		assert.Equal(t, "0.1.0", infos.RequiredPluginVersions[0].Version)

		// check list elements
		require.Len(t, infos.Lists, 2)

		assert.Equal(t, "cat_binaries", infos.Lists[0].Info.Name)
		require.Len(t, infos.Lists[0].Info.Items, 1)
		assert.Equal(t, "cat", infos.Lists[0].Info.Items[0])
		assert.True(t, infos.Lists[0].Details.Used)
		assert.Len(t, infos.Lists[0].Details.Lists, 0)
		assert.Len(t, infos.Lists[0].Details.Plugins, 0)
		assert.Len(t, infos.Lists[0].Details.ItemsCompiled, 1)
		assert.Equal(t, "cat", infos.Lists[0].Info.Items[0])

		assert.Equal(t, "cat_capable_binaries", infos.Lists[1].Info.Name)
		assert.Len(t, infos.Lists[1].Info.Items, 0)
		assert.True(t, infos.Lists[1].Details.Used)
		require.Len(t, infos.Lists[1].Details.Lists, 1)
		assert.Equal(t, "cat_binaries", infos.Lists[1].Details.Lists[0])
		assert.Len(t, infos.Lists[1].Details.Plugins, 0)
		require.Len(t, infos.Lists[1].Details.ItemsCompiled, 1)
		assert.Equal(t, "cat", infos.Lists[1].Details.ItemsCompiled[0])

		// check macro elements
		require.Len(t, infos.Macros, 1)

		assert.Equal(t, "is_cat", infos.Macros[0].Info.Name)
		assert.Equal(t, "proc.name in (cat_capable_binaries)", infos.Macros[0].Info.Condition)
		assert.True(t, infos.Macros[0].Details.Used)
		assert.Len(t, infos.Macros[0].Details.Macros, 0)
		assert.Len(t, infos.Macros[0].Details.Lists, 1)
		assert.Equal(t, "cat_capable_binaries", infos.Macros[0].Details.Lists[0])
		assert.Len(t, infos.Macros[0].Details.Plugins, 0)
		assert.NotEmpty(t, infos.Macros[0].Details.Events)
		assert.Len(t, infos.Macros[0].Details.ConditionOperators, 1)
		assert.Equal(t, "in", infos.Macros[0].Details.ConditionOperators[0])
		require.Len(t, infos.Macros[0].Details.ConditionFields, 1)
		assert.Equal(t, "proc.name", infos.Macros[0].Details.ConditionFields[0])
		assert.Equal(t, "proc.name in (cat)", infos.Macros[0].Details.ConditionCompiled)

		// check rule elements
		require.Len(t, infos.Rules, 1)

		assert.Equal(t, "open_from_cat", infos.Rules[0].Info.Name)
		assert.Equal(t, `evt.type=open and is_cat and json.value[/test] = "test"`, infos.Rules[0].Info.Condition)
		assert.Equal(t, "A process named cat does an open", infos.Rules[0].Info.Description)
		assert.Equal(t, "An open was seen (command=%proc.cmdline)", infos.Rules[0].Info.Output)
		assert.Equal(t, true, infos.Rules[0].Info.Enabled)
		assert.Equal(t, "Warning", infos.Rules[0].Info.Priority)
		assert.Equal(t, "syscall", infos.Rules[0].Info.Source)
		assert.Empty(t, infos.Rules[0].Info.Tags)
		require.Len(t, infos.Rules[0].Details.Plugins, 1)
		assert.Equal(t, "json", infos.Rules[0].Details.Plugins[0])
		require.Len(t, infos.Rules[0].Details.OutputFields, 1)
		assert.Equal(t, "proc.cmdline", infos.Rules[0].Details.OutputFields[0])
		assert.Equal(t, infos.Rules[0].Info.Output, infos.Rules[0].Details.OutputCompiled)
		assert.Len(t, infos.Rules[0].Details.Macros, 1)
		require.Equal(t, "is_cat", infos.Rules[0].Details.Macros[0])
		assert.Len(t, infos.Rules[0].Details.Lists, 0)
		assert.Len(t, infos.Rules[0].Details.ExceptionFields, 0)
		assert.Len(t, infos.Rules[0].Details.ExceptionOperators, 0)
		assert.Len(t, infos.Rules[0].Details.ExceptionNames, 0)
		assert.Len(t, infos.Rules[0].Details.Events, 2)
		assert.Contains(t, infos.Rules[0].Details.Events, "open")
		assert.Contains(t, infos.Rules[0].Details.Events, "asyncevent")
		assert.Len(t, infos.Rules[0].Details.ConditionOperators, 2)
		assert.Contains(t, infos.Rules[0].Details.ConditionOperators, "=")
		assert.Contains(t, infos.Rules[0].Details.ConditionOperators, "in")
		assert.Len(t, infos.Rules[0].Details.ConditionFields, 3)
		assert.Contains(t, infos.Rules[0].Details.ConditionFields, "evt.type")
		assert.Contains(t, infos.Rules[0].Details.ConditionFields, "proc.name")
		assert.Contains(t, infos.Rules[0].Details.ConditionFields, "json.value[/test]")
		assert.Equal(t, `(evt.type = open and proc.name in (cat) and json.value[/test] = test)`, infos.Rules[0].Details.ConditionCompiled)
	})
}

func TestFlaco_Rule_Info(t *testing.T) {
	t.Parallel()
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("valid-rule-name", func(t *testing.T) {
		res := falco.Test(
			runner,
			falco.WithRules(rules.DisabledRuleUsingEnabledFlagOnly),
			falco.WithArgs("-l"),
			falco.WithArgs("open_from_cat"),
		)
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Regexp(t,
			`.*Rule[\s]+Description[\s]+`+
				`[\-]+[\s]+[\-]+[\s]+`+
				`open_from_cat[\s]+A process named cat does an open`,
			res.Stdout())
	})
	t.Run("invalid-rule-name", func(t *testing.T) {
		res := falco.Test(
			runner,
			falco.WithRules(rules.DisabledRuleUsingEnabledFlagOnly),
			falco.WithArgs("-l"),
			falco.WithArgs("invalid"),
		)
		assert.Error(t, res.Err(), "%s", res.Stderr())
	})
}

func TestFalco_Cmd_Help(t *testing.T) {
	t.Parallel()
	runner := tests.NewFalcoExecutableRunner(t)
	tests := []struct {
		name string
		args []string
	}{
		{name: "-h flag", args: []string{"-h"}},
		{name: "--help flag", args: []string{"--help"}},
	}

	// Falco 0.41
	helpList := []string{
		"-h", "--help",
		"-c",
		"--config-schema",
		"--rule-schema",
		"--disable-source",
		"--dry-run",
		"--enable-source",
		"-i",
		"-L",
		"-l",
		"--list",
		"--list-events",
		"--list-plugins",
		"-M",
		"--markdown",
		"-N",
		"-o", "--option",
		"--plugin-info",
		"-p", "--print",
		"-P", "--pidfile",
		"-r",
		"--support",
		"-U", "--unbuffered",
		"-V", "--validate",
		"-v",
		"--version",
		"--page-size",
	}
	// Gvisor is amd64 only:
	// https://github.com/falcosecurity/libs/blob/d1f550a596b2f04db7b5853bb92c68baeeae8cb1/cmake/modules/engine_config.cmake#L26
	if runtime.GOARCH == "amd64" {
		helpList = append(helpList, "--gvisor-generate-config")
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := falco.Test(runner, falco.WithArgs(tc.args...))
			assert.NoError(t, res.Err(), "%s", res.Stderr())
			assert.Equal(t, res.ExitCode(), 0)

			out := res.Stdout()

			assert.Contains(t, out, "Usage:")
			assert.Contains(t, out, "falco [OPTION...]")
			for _, output := range helpList {
				assert.Contains(t, out, output)
			}
		})
	}
}
