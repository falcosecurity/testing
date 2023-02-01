package falco

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

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

type Detections []*Alert

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

func (d Detections) ForPriority(p string) Detections {
	return d.filter(func(a *Alert) bool {
		// note: we need to use "CONTAINS" because of
		// the INFO -> INFORMATIONAL changes we had in the past
		return strings.Contains(strings.ToLower(a.Priority), strings.ToLower(p))
	})
}

func (d Detections) ForRule(v interface{}) Detections {
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

func (d Detections) Count() int {
	return len(d)
}
