package tests

import (
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
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
