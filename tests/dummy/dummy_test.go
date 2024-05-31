package testdummy

import (
	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/pkg/run"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/plugins"
	"github.com/falcosecurity/testing/tests/data/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"sync"
	"testing"
	"time"
)

func runFalcoWithDummy(t *testing.T, r run.Runner, opts ...falco.TestOption) *falco.TestOutput {
	config, err := falco.NewPluginConfig(
		"plugin-config.yaml",
		&falco.PluginConfigInfo{
			Name:       "dummy",
			Library:    plugins.DummyPlugin.Name(),
			OpenParams: `'{"start": 1, "maxEvents": 2000000000}'`,
		},
	)
	require.Nil(t, err)
	options := []falco.TestOption{
		falco.WithEnabledSources("dummy"),
		falco.WithConfig(config),
		falco.WithExtraFiles(plugins.DummyPlugin),
	}
	options = append(options, opts...)
	return falco.Test(r, options...)
}

func TestDummy_PrometheusMetrics(t *testing.T) {
	var (
		wg         sync.WaitGroup
		metricsErr error
	)
	wg.Add(1)

	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Second)
		_, metricsErr = http.Get("http://127.0.0.1:8765/metrics")
	}()

	falcoRes := runFalcoWithDummy(t,
		tests.NewFalcoExecutableRunner(t),
		falco.WithPrometheusMetrics(),
		falco.WithRules(rules.SingleRule),
		falco.WithStopAfter(5*time.Second),
		falco.WithArgs("-o", "engine.kind=nodriver"),
	)
	assert.NoError(t, falcoRes.Err(), "%s", falcoRes.Stderr())
	assert.Equal(t, 0, falcoRes.ExitCode())

	wg.Wait()

	assert.NoError(t, metricsErr)
}
