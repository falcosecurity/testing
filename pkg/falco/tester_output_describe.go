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
	"encoding/json"

	"github.com/sirupsen/logrus"
)

// RulesetDescription represent the description of the knowledge of the Falco
// engine after loading one or more rules files.
type RulesetDescription struct {
	RequiredEngineVersion  string                                `json:"required_engine_version"`
	RequiredPluginVersions []PluginVersionRequirementDescription `json:"required_plugin_versions"`
	Lists                  []ListDescription                     `json:"lists"`
	Macros                 []MacroDescription                    `json:"macros"`
	Rules                  []RuleDescription                     `json:"rules"`
}

type PluginVersionRequirement struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PluginVersionRequirementDescription struct {
	Alternatives []PluginVersionRequirement `json:"alternatives"`
	PluginVersionRequirement
}

type ListDetailsDescription struct {
	ItemsCompiled []string `json:"items_compiled"`
	Lists         []string `json:"lists"`
	Plugins       []string `json:"plugins"`
	Used          bool     `json:"used"`
}

type ListInfoDescription struct {
	Items []string `json:"items"`
	Name  string   `json:"name"`
}

type ListDescription struct {
	Details ListDetailsDescription `json:"details"`
	Info    ListInfoDescription    `json:"info"`
}

type MacroDetailsDescription struct {
	ConditionCompiled  string   `json:"condition_compiled"`
	ConditionFields    []string `json:"condition_fields"`
	ConditionOperators []string `json:"condition_operators"`
	Events             []string `json:"events"`
	Lists              []string `json:"lists"`
	Macros             []string `json:"macros"`
	Plugins            []string `json:"plugins"`
	Used               bool     `json:"used"`
}

type MacroInfoDescription struct {
	Condition string `json:"condition"`
	Name      string `json:"name"`
}

type MacroDescription struct {
	Details MacroDetailsDescription `json:"details"`
	Info    MacroInfoDescription    `json:"info"`
}

type RuleDetailsDescription struct {
	ConditionCompiled  string   `json:"condition_compiled"`
	ConditionFields    []string `json:"condition_fields"`
	ConditionOperators []string `json:"condition_operators"`
	Events             []string `json:"events"`
	ExceptionFields    []string `json:"exception_fields"`
	ExceptionNames     []string `json:"exception_names"`
	ExceptionOperators []string `json:"exception_operators"`
	Lists              []string `json:"lists"`
	Macros             []string `json:"macros"`
	OutputCompiled     string   `json:"output_compiled"`
	OutputFields       []string `json:"output_fields"`
	Plugins            []string `json:"plugins"`
}

type RuleInfoDescription struct {
	Condition   string   `json:"condition"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Name        string   `json:"name"`
	Output      string   `json:"output"`
	Priority    string   `json:"priority"`
	Source      string   `json:"source"`
	Tags        []string `json:"tags"`
}

type RuleDescription struct {
	Details RuleDetailsDescription `json:"details"`
	Info    RuleInfoDescription    `json:"info"`
}

// RulesetDescription converts the output of the Falco run into a an struct
// describing the knowledge of the Falco engine after loading one or more rules files.
// This is achieved with the Falco `-L` option combined with the JSON output enabled.
// Returns nil if Falco wasn't run for rules descriptions.
func (t *TestOutput) RulesetDescription() *RulesetDescription {
	if !t.hasOutputJSON() {
		logrus.Errorf("TestOutput.RulesetDescription: must use WithOutputJSON")
	}

	res := &RulesetDescription{}
	if err := json.Unmarshal([]byte(t.Stdout()), res); err != nil {
		logrus.WithField("stdout", t.Stdout()).Errorf("TestOutput.RulesetDescription: can't parse stdout JSON")
		return nil
	}
	return res
}
