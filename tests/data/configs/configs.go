package configs

import "github.com/falcosecurity/falco/regression-tests/pkg/utils"

//go:generate go run generate.go

var EmptyConfig = utils.NewStringFileAccessor("empty_config.yaml", "")
