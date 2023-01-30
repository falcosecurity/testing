package configs

import "github.com/jasondellaluce/falco-testing/pkg/run"

//go:generate go run generate.go

var EmptyConfig = run.NewStringFileAccessor("empty_config.yaml", "")
