package testfalco

import (
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/configs"

	"github.com/stretchr/testify/assert"
)

// todo(jasondellaluce): implement tests for the non-covered Falco config fields:
//   watch_config_files, libs_logger, buffered_outputs, syscall_event_timeouts,
//   syscall_buf_size_preset, modern_bpf, output_timeout, outputs
//   syslog_output, file_output, stdout_output, webserver, program_output,
//   http_output, metadata_download
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

func TestFalco_Miscs_StartupFail(t *testing.T) {
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("empty-config", func(t *testing.T) {
		res := falco.Test(runner, falco.WithConfig(configs.EmptyConfig))
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 1)
		assert.Contains(t, res.Stderr(), "You must specify at least one rules file")
	})
}
