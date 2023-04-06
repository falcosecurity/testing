package outputs

import (
	_ "embed"

	"github.com/falcosecurity/testing/pkg/run"
)

//go:embed IgnoredEvents.txt
var events string
var EventData = run.NewStringFileAccessor("eventData", events)

//go:embed Rules.txt
var rules string
var Rules = run.NewStringFileAccessor("rulesData", rules)
