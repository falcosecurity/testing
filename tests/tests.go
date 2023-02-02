package tests

import (
	"os"
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/pkg/falcoctl"
	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// todo: manage test envvars/arguments here

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

func NewFalcoExecutableRunner(t *testing.T) run.Runner {
	runner, err := run.NewExecutableRunner(falco.DefaultExecutable)
	require.Nil(t, err)
	return runner
}

func NewFalcoctlExecutableRunner(t *testing.T) run.Runner {
	if _, err := os.Stat(falcoctl.DefaultLocalExecutable); err != nil {
		logrus.Debug("using falcoctl default executable location")
		runner, err := run.NewExecutableRunner(falcoctl.DefaultExecutable)
		require.Nil(t, err)
		return runner
	}
	logrus.Debug("using falcoctl default local executable location")
	runner, err := run.NewExecutableRunner(falcoctl.DefaultLocalExecutable)
	require.Nil(t, err)
	return runner
}
