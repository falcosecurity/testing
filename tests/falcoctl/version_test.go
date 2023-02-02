package testfalcoctl

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falcoctl"
	"github.com/jasondellaluce/falco-testing/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	t.Run("invalid-extra-cmd", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version", "some_other_cmd"),
		)
		assert.NotNil(t, res.Err(), "%s", res.Stderr())
		assert.NotZero(t, res.ExitCode())
		assert.Contains(t, res.Stderr(), `Error: unknown command "some_other_cmd"`)
	})

	t.Run("version-plaintext", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version"),
		)
		assert.Nil(t, res.Err(), "%s", res.Stderr())
		assert.Zero(t, res.ExitCode())
		assert.Regexp(t, `Client Version:[\s]+[0-9]+.[0-9]+.[0-9]+(-[a-z]+[0-9]+)?`, res.Stdout())
	})

	t.Run("version-json", func(t *testing.T) {
		t.Parallel()
		res := falcoctl.Test(
			tests.NewFalcoctlExecutableRunner(t),
			falcoctl.WithArgs("version", "--output=json"),
		)
		assert.Nil(t, res.Err(), "%s", res.Stderr())
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
		assert.Nil(t, res.Err(), "%s", res.Stderr())
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
