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

package testfalco

import (
	"os"
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/configs"

	"github.com/stretchr/testify/assert"
)

// todo(jasondellaluce): implement tests for the non-covered Falco config fields:
//   watch_config_files, libs_logger, buffered_outputs, syscall_event_timeouts,
//   syslog_output, file_output, stdout_output, webserver, program_output,
//   http_output, metadata_download, output_timeout, outputs
//
// todo(jasondellaluce): test Falco behavior on environment variables and their
// priorities in combination with their args/configs/cmds counterparts:
//   FALCO_K8S_API, FALCO_K8S_API_CERT, FALCO_MESOS_API, FALCO_HOSTNAME,
//   FALCO_GRPC_HOSTNAME, FALCO_BPF_PROBE, HOME (used for bpf probe)
//
// todo(jasondellaluce): implement tests for Falco reaction to signals:
//   SIGINT, SIGUSR1, SIGHUP
//
// todo(jasondellaluce): implement tests for other non-covered Falco things:
//   - collection of live events with kmod, bpf, modern-bpf, gvisor, userspace
//   - collection of live events with multiple event sources active at the same
//   - stress test with event generator, checking memory usage and event drops

// checkConfig skips a test if the default configuration filepath
// is not available in the local filesystem.
func checkConfig(t *testing.T) {
	if _, err := os.Stat(falco.FalcoConfig); err != nil {
		t.Skipf("could not find Falco config at %s: %s", falco.FalcoConfig, err.Error())
	}
}

// checkNotStaticExecutable is Falco executables use a static binary build.
func checkNotStaticExecutable(t *testing.T) {
	if tests.IsStaticFalcoExecutable() {
		t.Skipf("test not available for static Falco builds")
	}
}

func TestFalco_Miscs_StartupFail(t *testing.T) {
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("empty-config", func(t *testing.T) {
		res := falco.Test(runner, falco.WithConfig(configs.EmptyConfig))
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 1)
		assert.Contains(t, res.Stderr(), "You must specify at least one rules file")
	})
}
