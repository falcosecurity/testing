package configs

import "github.com/jasondellaluce/falco-testing/pkg/utils"

//go:generate go run generate.go

var EmptyConfig = utils.NewStringFileAccessor("empty_config.yaml", "")
