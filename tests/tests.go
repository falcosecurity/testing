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

var (
	falcoStatic    = false
	falcoBinary    = falco.DefaultExecutable
	falcoctlBinary = falcoctl.DefaultLocalExecutable
)

func init() {
	flag.BoolVar(&falcoStatic, "falco-static", falcoStatic, "True if the Falco executable is from a static build")
	flag.StringVar(&falcoBinary, "falco-binary", falcoBinary, "Falco executable binary path")
	flag.StringVar(&falcoctlBinary, "falcoctl-binary", falcoctlBinary, "falcoctl executable binary path")
	flag.StringVar(&falco.FalcoConfig, "falco-config", falco.FalcoConfig, "Falco config file path")

	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

// NewFalcoExecutableRunner returns an executable runner for Falco.
func NewFalcoExecutableRunner(t *testing.T) run.Runner {
	runner, err := run.NewExecutableRunner(falcoBinary)
	require.Nil(t, err)
	return runner
}

// NewFalcoctlExecutableRunner returns an executable runner for falcoctl.
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

// IsStaticFalcoExecutable returns true if Falco executables use a static build.
func IsStaticFalcoExecutable() bool {
	return falcoStatic
}
