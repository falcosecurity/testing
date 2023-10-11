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
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Alert represent an alert produced by a Falco rule.
type Alert struct {
	Time         time.Time              `json:"time"`
	Rule         string                 `json:"rule"`
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Source       string                 `json:"source"`
	Hostname     string                 `json:"hostname"`
	Tags         []string               `json:"tags"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

// Detections represents a list of Falco alerts.
type Detections []*Alert

// Detections converts the output of the Falco run into a list of rule detections.
// Returns nil if Falco wasn't run for rules detection.
func (t *TestOutput) Detections() Detections {
	if !t.hasOutputJSON() {
		logrus.Errorf("TestOutput.Detections: must use WithOutputJSON")
	}

	lines, err := readLineByLine(strings.NewReader(t.Stdout()))
	if err != nil {
		logrus.WithError(err).Errorf("TestOutput.Detections: can't read stdout line by line")
		return nil
	}
	var res Detections
	for _, line := range lines {
		alert := Alert{}
		if err := json.Unmarshal([]byte(line), &alert); err != nil {
			logrus.WithField("line", line).Tracef("TestOutput.Detections: stdout line not JSON")
			continue
		}
		res = append(res, &alert)
	}
	return res
}

func (d Detections) filter(f func(*Alert) bool) Detections {
	var res Detections
	for _, a := range d {
		if f(a) {
			res = append(res, a)
		}
	}
	return res
}

// OfPriority returns the list of detections that have a given priority.
func (d Detections) OfPriority(p string) Detections {
	return d.filter(func(a *Alert) bool {
		// note: we need to use "CONTAINS" because of
		// the INFO -> INFORMATIONAL changes we had in the past
		return strings.Contains(strings.ToLower(a.Priority), strings.ToLower(p))
	})
}

// OfRule returns the list of detections that have a given rule name.
// The rule name can either be a string or a *regexp.Regexp.
func (d Detections) OfRule(v interface{}) Detections {
	return d.filter(func(a *Alert) bool {
		if rgx, ok := v.(*regexp.Regexp); ok {
			return rgx.MatchString(a.Rule)
		}
		if str, ok := v.(string); ok {
			return a.Rule == str
		}
		panic("argument must be string or *regexp.Regexp")
	})
}

// Count returns the amount of alerts in the list of detections.
func (d Detections) Count() int {
	return len(d)
}
