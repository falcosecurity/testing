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
