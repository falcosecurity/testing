package tests

import (
	"testing"

	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/jasondellaluce/falco-testing/tests/falco/data/captures"
	"github.com/jasondellaluce/falco-testing/tests/falco/data/plugins"
	"github.com/jasondellaluce/falco-testing/tests/falco/data/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runFalcoWithK8SAudit(t *testing.T, r run.Runner, input run.FileAccessor, opts ...falco.TestOption) *falco.TestOutput {
	config, err := falco.NewPluginConfig(
		&falco.PluginConfigInfo{
			Name:       "k8saudit",
			Library:    plugins.K8SAuditPlugin.Name(),
			OpenParams: input.Name(),
		},
		&falco.PluginConfigInfo{
			Name:    "json",
			Library: plugins.JSONPlugin.Name(),
		},
	)
	require.Nil(t, err)
	options := []falco.TestOption{
		falco.WithEnabledSources("k8s_audit"),
		falco.WithConfig(config),
		falco.WithExtraFiles(input, plugins.K8SAuditPlugin, plugins.JSONPlugin),
	}
	options = append(options, opts...)
	return falco.Test(r, options...)
}

func TestLegacy_CreateSensitiveMountPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodSensitiveMount,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Sensitive Mount Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateService(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateService,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Service Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteConfigmap(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteConfigmap,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s ConfigMap Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateNamespace(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditSomeUserCreatesNamespaceFoo,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowNamespaceFoo,
			rules.K8SAuditAllowUserSomeUser),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Namespace Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteDeployment(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteDeployment,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Deployment Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteClusterrolebinding(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteClusterrolebinding,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Role/Clusterrolebinding Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreateDisallowedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditEngineV4K8SAuditRules,
			rules.K8SAuditEngineV4AllowOnlyApacheContainer),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Disallowed Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreateHostnetworkPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodHostnetwork,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditEngineV4K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create HostNetwork Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePodExecClusterRole(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateClusterRolePodExec,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("ClusterRole With Pod Exec Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateConfigmap(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateConfigmap,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s ConfigMap Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreatePrivilegedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodPrivileged,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditEngineV4K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Privileged Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_NamespaceInAllowedSet(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditMinikubeCreatesNamespaceFoo,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowNamespaceFoo,
			rules.K8SAuditDisallowKactivity),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateServiceaccountInKubePublicNamespace(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateServiceaccountKubePublicNamespace,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Service Account Created in Kube Namespace").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateDeployment(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateDeployment,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Deployment Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteNamespace(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteNamespaceFoo,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Namespace Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_JsonPointerCorrectParse(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithOutputJSON(),
		falco.WithRules(rules.K8SAuditSingleRuleWithJsonPointer),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("json_pointer_example").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateDisallowedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowOnlyApacheContainer),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Disallowed Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateNohostnetworkPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodNohostnetwork,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateNonodeportService(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxServiceNonodeport,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditDisallowKactivity),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePodInKubePublicNamespace(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreatePodKubePublicNamespace,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Pod Created in Kube Namespace").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateClusterRoleWildcardResources(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateClusterRoleWildcardResources,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("ClusterRole With Wildcard Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_SystemClusterroleDeleted(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteClusterRoleKubeAggregator,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("System ClusterRole Modified/Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreateAllowedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditEngineV4K8SAuditRules,
			rules.K8SAuditEngineV4AllowNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreatePrivilegedTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodPrivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditEngineV4K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateUnsensitiveMountPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnsensitiveMount,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateNodeportService(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxServiceNodeport,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditDisallowKactivity),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create NodePort Service").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_NamespaceOutsideAllowedSet(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditSomeUserCreatesNamespaceFoo,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowUserSomeUser),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Disallowed Namespace").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteSecret(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteSecret,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Secret Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateSensitiveMountTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodSensitiveMount,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_PodExec(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditExecPod,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Attach/Exec Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_PodAttach(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditAttachPod,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Attach/Exec Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateServiceaccountInKubeSystemNamespace(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateServiceaccountKubeSystemNamespace,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Service Account Created in Kube Namespace").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_AttachClusterAdminRole(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditAttachClusterAdminRole,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Attach to cluster-admin Role").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreateUnprivilegedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditEngineV4K8SAuditRules),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePrivilegedNoSecctx1StContainer2NdContainerPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodNoSecctx1StContainerPrivileged2NdContainer,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Privileged Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateUnsensitiveMountTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnsensitiveMount,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePrivileged2NdContainerPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodPrivileged2NdContainer,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Privileged Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateHostnetworkTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodHostnetwork,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateServiceaccount(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateServiceaccount,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Serviceaccount Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateKubeSystemSecret(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateKubeSystemSecret,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("INFO").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_UserInAllowedSet(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditSomeUserCreatesNamespaceFoo,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowNamespaceFoo,
			rules.K8SAuditAllowUserSomeUser,
			rules.K8SAuditDisallowKactivity),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateClusterRoleWildcardVerbs(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateClusterRoleWildcardVerbs,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("ClusterRole With Wildcard Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateWritableClusterRole(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateClusterRoleWritePrivileges,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().ForRule("ClusterRole With Write Privileges Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteClusterrole(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteClusterrole,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Role/Clusterrole Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateSecret(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateSecret,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Secret Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CompatEngineV4CreateHostnetworkTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodHostnetwork,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditEngineV4K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateSensitiveMount2NdContainerPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodSensitiveMount2NdContainer,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Sensitive Mount Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteServiceaccount(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteServiceaccount,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Serviceaccount Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateClusterrole(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateClusterrole,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Role/Clusterrole Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateClusterrolebinding(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateClusterrolebinding,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Role/Clusterrolebinding Created").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateAllowedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateUnprivilegedTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateNohostnetworkTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodNohostnetwork,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePrivilegedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodPrivileged,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create Privileged Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateConfigmapPrivateCreds(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateConfigmapSensitiveValues,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditDisallowKactivity),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 6, res.Detections().ForRule("Create/Modify Configmap With Private Credentials").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateConfigmapNoPrivateCreds(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateConfigmapNoSensitiveValues,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditDisallowKactivity),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePrivilegedTrustedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodPrivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditTrustNginxContainer),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateHostnetworkPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodHostnetwork,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Create HostNetwork Pod").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_AnonymousUser(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditAnonymousCreatesNamespaceFoo,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Anonymous Request Allowed").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_SystemClusterroleModified(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditModifyClusterRoleNodeProblemDetector,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("System ClusterRole Modified/Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_Fal01003(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditFal01003,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.Regexp(t, `data not recognized as a k8s audit event`, res.Stderr())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_UserOutsideAllowedSet(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditSomeUserCreatesNamespaceFoo,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules,
			rules.K8SAuditAllowNamespaceFoo),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Disallowed K8s User").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateUnprivilegedPod(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateNginxPodUnprivileged,
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreatePodInKubeSystemNamespace(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreatePodKubeSystemNamespace,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().ForRule("Pod Created in Kube Namespace").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_DeleteService(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditDeleteService,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().ForPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().ForRule("K8s Service Deleted").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestLegacy_CreateServiceAccountTokenSecret(t *testing.T) {
	t.Parallel()
	res := runFalcoWithK8SAudit(t,
		newExecutableRunner(t),
		captures.K8SAuditCreateServiceAccountTokenSecret,
		falco.WithOutputJSON(),
		falco.WithRules(
			rules.FalcoRules,
			rules.K8SAuditRules),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().ForPriority("INFO").Count())
	assert.Nil(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}
