package plugins

import "github.com/falcosecurity/testing/pkg/run"

var K8SAuditPlugin = run.NewLocalFileAccessor(
	"libk8saudit.so",
	"/usr/share/falco/plugins/libk8saudit.so",
)

var CloudtrailPlugin = run.NewLocalFileAccessor(
	"libcloudtrail.so",
	"/usr/share/falco/plugins/libcloudtrail.so",
)

var JSONPlugin = run.NewLocalFileAccessor(
	"libjson.so",
	"/usr/share/falco/plugins/libjson.so",
)
