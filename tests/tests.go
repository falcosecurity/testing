package tests

import (
	"flag"
	"os"
	"os/user"
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/pkg/falcoctl"
	"github.com/falcosecurity/testing/pkg/run"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var falcoBinary = falco.DefaultExecutable
var falcoctlBinary = falcoctl.DefaultLocalExecutable

func init() {
	flag.StringVar(&falcoBinary, "falco-binary", falcoBinary, "Falco executable binary path")
	flag.StringVar(&falcoctlBinary, "falcoctl-binary", falcoctlBinary, "falcoctl executable binary path")
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

// NewFalcoctlExecutableRunner returns an executable runner for Falco
func NewFalcoExecutableRunner(t *testing.T) run.Runner {
	runner, err := run.NewExecutableRunner(falcoBinary)
	require.Nil(t, err)
	return runner
}

// NewFalcoctlExecutableRunner returns an executable runner for falcoctl
func NewFalcoctlExecutableRunner(t *testing.T) run.Runner {
	if _, err := os.Stat(falcoctlBinary); err == nil {
		runner, err := run.NewExecutableRunner(falcoctlBinary)
		require.Nil(t, err)
		return runner
	}
	logrus.Debug("using falcoctl default executable location")
	runner, err := run.NewExecutableRunner(falcoctl.DefaultExecutable)
	require.Nil(t, err)
	return runner
}

// IsRootUser returns true if the program is run as root.
func IsRootUser(t *testing.T) bool {
	currentUser, err := user.Current()
	require.Nil(t, err)
	return currentUser.Uid == "0"
}

// IsInContainer returns true if the program is run inside a container.
func IsInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}
