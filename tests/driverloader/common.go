package tests

import (
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/driverloader"
	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

func newExecutableRunner(t *testing.T) run.Runner {
	runner, err := run.NewExecutableRunner(driverloader.DefaultExecutable)
	require.Nil(t, err)
	return runner
}

func newDockerRunner(t *testing.T) run.Runner {
	runner, err := run.NewDockerRunner(
		"falcosecurity/falco-driver-loader:master",
		driverloader.DefaultExecutable,
		&run.DockerRunnerOptions{
			Privileged: true,
			Binds:      driverloader.DockerBinds,
		},
	)
	require.Nil(t, err)
	return runner
}
