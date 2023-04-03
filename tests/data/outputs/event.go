package outputs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/falcosecurity/testing/pkg/run"
)

type Data struct {
	Events []string `json:"events"`
}

func deserialize() string {
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		panic("not able to extract runtime caller info")
	}
	dir, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		panic(err)
	}
	filePath := filepath.Join(dir, "events.json")
	evntfile, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer evntfile.Close()

	var events Data
	err = json.NewDecoder(evntfile).Decode(&events)
	if err != nil {
		panic(err)
	}
	return strings.Join(events.Events, ",")
}

var EventData = run.NewStringFileAccessor("eventData", deserialize())
