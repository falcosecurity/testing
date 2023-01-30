package tests

import (
	"testing"

	"github.com/falcosecurity/falco/regression-tests/pkg/falco"
	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var (
	falcoRules            = utils.NewLocalFileAccessor("falco_rules.yaml", "/etc/falco/falco_rules.yaml")
	K8SAuditPluginLibrary = utils.NewLocalFileAccessor("libk8saudit.so", "/usr/share/falco/plugins/libk8saudit.so")
	JSONPluginLibrary     = utils.NewLocalFileAccessor("libjson.so", "/usr/share/falco/plugins/libjson.so")
)

func TestK8SAudit(t *testing.T) {
	input := utils.NewLocalFileAccessor("input.json", "/home/vagrant/dev/falcosecurity/falco/test/trace_files/k8s_audit/create_nginx_pod_privileged.json")
	rules := utils.NewLocalFileAccessor("k8saudit_rules.yaml", "/home/vagrant/dev/falcosecurity/falco/test/rules/k8s_audit/engine_v4_k8s_audit_rules.yaml")
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

	runner := falco.NewExecutableRunner(FalcoExecutable)
	res := falco.TestRun(runner,
		falco.TestWithOutputJSON(),
		falco.TestWithConfig(config),
		falco.TestWithRules(falcoRules, rules),
		falco.TestWithEnabledSources("k8s_audit"),
		falco.TestWithExtraFiles(input, K8SAuditPluginLibrary, JSONPluginLibrary),
	)
	println(res.Stderr())
	assert.Nil(t, res.Err())
	assert.Equal(t, 0, res.ExitCode())
	assert.Equal(t, 1, res.Detections().ForRule("Create Privileged Pod").Count())
}
