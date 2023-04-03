package outputs

import (
	_ "embed"

	"github.com/falcosecurity/testing/pkg/run"
)

//go:embed events.txt
var s string
var EventData = run.NewStringFileAccessor("eventData", s)
