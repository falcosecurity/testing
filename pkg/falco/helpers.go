// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package falco

import (
	"bytes"
	"encoding/json"
	"os"
	"text/template"

	"github.com/falcosecurity/testing/pkg/run"
)

// PluginConfigInfo represents the info about a single plugin
// in a Falco configuration file (i.e. falco.yaml). InitConfig can
// be either a string or a json-serializable object.
type PluginConfigInfo struct {
	Name       string
	Library    string
	OpenParams string
	InitConfig interface{}
}

func (p *PluginConfigInfo) InitConfigString() string {
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
func NewPluginConfig(configName string, plugins ...*PluginConfigInfo) (run.FileAccessor, error) {
	var buf bytes.Buffer

	// If we are running a newer Falco version with
	// the container plugin, enforce it to the
	if _, err := os.Stat(FalcoContainerPluginLibrary); err == nil {
		plugins = append(plugins, &PluginConfigInfo{
			Name:    "container",
			Library: FalcoContainerPluginLibrary,
		})
	}

	err := template.Must(template.New("").Parse(`
stdout_output:
  enabled: true
plugins:
{{ range $i, $p := . }}  - name: {{ $p.Name }}
    library_path: {{ $p.Library }}{{ if $p.InitConfig }}
    init_config: {{ $p.InitConfigString }}{{ end }}{{ if $p.OpenParams }}
    open_params: {{ $p.OpenParams }}{{ end }}
{{ end }}load_plugins:{{ range $i, $p := . }}
  - {{ $p.Name }}
{{ end }}
`)).Execute(&buf, plugins)
	if err != nil {
		return nil, err
	}
	return run.NewStringFileAccessor(configName, buf.String()), err
}
