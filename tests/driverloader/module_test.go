package tests

import (
	"bytes"
	"context"
	"os/user"
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/driverloader"
	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkPrivileges(t *testing.T) {
	currentUser, err := user.Current()
	require.Nil(t, err)
	if currentUser.Uid != "0" {
		t.Skip("this test must be run as root")
	}
}

func removeModule(t *testing.T) {
	ok, err := driverloader.CheckModule()
	require.Nil(t, err)
	if ok {
		err = driverloader.RemoveModule()
		require.Nil(t, err)
	}
	ok, err = driverloader.CheckModule()
	require.Nil(t, err)
	require.False(t, ok)
}

func runFalco(t *testing.T, bpf bool) {
	runner, err := run.NewDockerRunner("falcosecurity/falco-no-driver:master", falco.DefaultExecutable, &run.DockerRunnerOptions{
		Binds:      falco.PrivilegedDockerBinds,
		Privileged: true,
	})
	require.Nil(t, err)
	opts := []falco.TestOption{
		falco.WithArgs("-M", "1"),
		falco.WithEnabledSources("syscall"),
	}
	if bpf {
		opts = append(opts, falco.WithArgs("--bpf_probe"))
	}
	res := falco.Test(
		runner,
		opts...,
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
}

func TestModule(t *testing.T) {
	checkPrivileges(t)
	t.Parallel()
	runner := newDockerRunner(t)

	t.Run("default", func(t *testing.T) {
		var stderr bytes.Buffer
		var stdout bytes.Buffer
		removeModule(t)
		err := runner.Run(
			context.Background(),
			run.WithStderr(&stderr),
			run.WithStdout(&stdout),
			run.WithArgs("module"),
		)
		require.Nil(t, err)
		ok, err := driverloader.CheckModule()
		require.Nil(t, err)
		require.True(t, ok)
		runFalco(t, false)
	})

}

func TestEbpfProbe(t *testing.T) {
	checkPrivileges(t)
	t.Parallel()
	runner := newDockerRunner(t)

	t.Run("default", func(t *testing.T) {
		var stderr bytes.Buffer
		var stdout bytes.Buffer
		removeModule(t)
		err := runner.Run(
			context.Background(),
			run.WithStderr(&stderr),
			run.WithStdout(&stdout),
			run.WithArgs("bpf"),
		)
		require.Nil(t, err)
		runFalco(t, true)
	})

}
