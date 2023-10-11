// SPDX-License-Identifier: Apache-2.0
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

package testfalcoctl

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/falcosecurity/testing/pkg/falcoctl"
	"github.com/falcosecurity/testing/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFalcoctl_Version(t *testing.T) {
	t.Parallel()

	t.Run("invalid-extra-cmd", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version", "some_other_cmd"),
		)
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.NotZero(t, res.ExitCode())
		assert.Contains(t, res.Stdout(), `unknown command "some_other_cmd"`)
	})

	t.Run("version-plaintext", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version"),
		)
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Zero(t, res.ExitCode())
		assert.Regexp(t, `Client Version:[\s]+[0-9]+.[0-9]+.[0-9]+(-[a-z]+[0-9]+)?`, res.Stdout())
	})

	t.Run("version-json", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version", "--output=json"),
		)
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		out := make(map[string]interface{})
		require.Nil(t, json.Unmarshal([]byte(res.Stdout()[strings.Index(res.Stdout(), "{"):]), &out))
		assert.Contains(t, out, "semVersion")
		assert.Contains(t, out, "gitCommit")
		assert.Contains(t, out, "buildDate")
		assert.Contains(t, out, "goVersion")
		assert.Contains(t, out, "compiler")
		assert.Contains(t, out, "platform")
	})

	t.Run("version-yaml", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version", "--output=yaml"),
		)
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		out := make(map[string]interface{})
		require.Nil(t, yaml.Unmarshal([]byte(res.Stdout()[strings.Index(res.Stdout(), ":\n")+1:]), &out))
		assert.Contains(t, out, "semversion")
		assert.Contains(t, out, "gitcommit")
		assert.Contains(t, out, "builddate")
		assert.Contains(t, out, "goversion")
		assert.Contains(t, out, "compiler")
		assert.Contains(t, out, "platform")
	})
}
