package tests

import (
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/jasondellaluce/falco-testing/tests/falco/data/captures"
	"github.com/jasondellaluce/falco-testing/tests/falco/data/rules"
	"github.com/stretchr/testify/assert"
)

var (
	falcoRules            = run.NewLocalFileAccessor("falco_rules.yaml", "/etc/falco/falco_rules.yaml")
	K8SAuditPluginLibrary = run.NewLocalFileAccessor("libk8saudit.so", "/usr/share/falco/plugins/libk8saudit.so")
	JSONPluginLibrary     = run.NewLocalFileAccessor("libjson.so", "/usr/share/falco/plugins/libjson.so")
)

func TestPlugins_K8SAudit(t *testing.T) {
	input := captures.K8SAuditCreateNginxPodPrivileged
	rules := rules.K8SAuditEngineV4K8SAuditRules

	config, err := falco.NewPluginConfig(
		&falco.PluginConfigInfo{
			Name:       "k8saudit",
			Library:    K8SAuditPluginLibrary.Name(),
			OpenParams: input.Name(),
		},
		&falco.PluginConfigInfo{
			Name:    "json",
			Library: JSONPluginLibrary.Name(),
		},
	)
	if err != nil {
		t.Fatal(err.Error())
	}

	runner := newExecutableRunner(t)
	res := falco.Test(runner,
		falco.WithOutputJSON(),
		falco.WithConfig(config),
		falco.WithRules(falcoRules, rules),
		falco.WithEnabledSources("k8s_audit"),
		falco.WithExtraFiles(input, K8SAuditPluginLibrary, JSONPluginLibrary),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.Equal(t, 1, res.Detections().ForRule("Create Privileged Pod").Count())
}
