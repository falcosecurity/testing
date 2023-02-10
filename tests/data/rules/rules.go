package rules

import "github.com/falcosecurity/testing/pkg/run"

//go:generate go run generate.go

var FalcoRules = run.NewLocalFileAccessor(
	"falco_rules.yaml",
	"/etc/falco/falco_rules.yaml",
)

var K8SAuditRules = run.NewLocalFileAccessor(
	" k8s_audit_rules.yaml",
	"/etc/falco/k8s_audit_rules.yaml",
)
