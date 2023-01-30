package falco

import (
	"bytes"
	"encoding/json"
	"text/template"

	"github.com/jasondellaluce/falco-testing/pkg/run"
)

// PluginInfo is a struct representing the info about a single plugin
// in a Falco configuration file (i.e. falco.yaml). InitConfig can
// be either a string or a json-serializable object.
type PluginConfigInfo struct {
	Name       string
	Library    string
	OpenParams string
	InitConfig interface{}
}

func (p *PluginConfigInfo) initConfigString() string {
	if p.InitConfig == nil {
		return ""
	}
	if str, ok := p.InitConfig.(string); ok {
		return str
	}
	str, err := json.Marshal(p.InitConfig)
	if err != nil {
		panic("PluginConfigInfo is neither a string or a json-serializable object: " + err.Error())
	}
	return string(str)
}

// NewPluginConfig helps creating valid Falco configuration files
// (i.e. falco.yaml) loading one or more plugins.
func NewPluginConfig(plugins ...*PluginConfigInfo) (run.FileAccessor, error) {
	var buf bytes.Buffer
	err := template.Must(template.New("").Parse(`
stdout_output:
  enabled: true
plugins:
{{ range $i, $p := . }}  - name: {{ $p.Name }}
    library_path: {{ $p.Library }}{{ if $p.InitConfig }}
    init_config: {{ call $p.initConfigString }}{{ end }}{{ if $p.OpenParams }}
    open_params: {{ $p.OpenParams }}{{ end }}
{{ end }}load_plugins:{{ range $i, $p := . }}
  - {{ $p.Name }}
{{ end }}
`)).Execute(&buf, plugins)
	if err != nil {
		return nil, err
	}
	return run.NewStringFileAccessor("plugin-config.yaml", buf.String()), err
}
