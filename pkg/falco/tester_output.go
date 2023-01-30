package falco

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/jasondellaluce/falco-testing/pkg/run"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
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

type RuleValidationInfo struct {
	Code     string `json:"code"`
	Codedesc string `json:"codedesc"`
	Message  string `json:"message"`
	Context  struct {
		Locations []struct {
			ItemName string `json:"item_name"`
			ItemType string `json:"item_type"`
			Position struct {
				Line   int    `json:"line"`
				Column int    `json:"column"`
				Offset int    `json:"offset"`
				Name   string `json:"name"`
			} `json:"position"`
		} `json:"locations"`
	} `json:"context"`
}

type RuleValidationInfos []*RuleValidationInfo

type RuleValidationResult struct {
	Successful bool                `json:"successful"`
	Name       string              `json:"name"`
	Errors     RuleValidationInfos `json:"errors"`
	Warnings   RuleValidationInfos `json:"warnings"`
}

var emptyRuleValidationResult = RuleValidationResult{}

type RuleValidation struct {
	Results []*RuleValidationResult `json:"falco_load_results"`
}

func (r RuleValidation) ForIndex(index int) *RuleValidationResult {
	if index >= len(r.Results) {
		return &emptyRuleValidationResult
	}
	return r.Results[index]
}

func (r RuleValidation) AllWarnings() RuleValidationInfos {
	var res RuleValidationInfos
	for _, result := range r.Results {
		res = append(res, result.Warnings...)
	}
	return res
}

func (r RuleValidation) AllErrors() RuleValidationInfos {
	var res RuleValidationInfos
	for _, result := range r.Results {
		res = append(res, result.Errors...)
	}
	return res
}

func (d RuleValidationInfos) filter(f func(*RuleValidationInfo) bool) RuleValidationInfos {
	var res RuleValidationInfos
	for _, a := range d {
		if f(a) {
			res = append(res, a)
		}
	}
	return res
}

func (d RuleValidationInfos) ForCode(v string) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		return strings.EqualFold(a.Code, v)
	})
}

func (d RuleValidationInfos) ForItemName(v string) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		for _, loc := range a.Context.Locations {
			if loc.ItemName == v {
				return true
			}
		}
		return false
	})
}

func (d RuleValidationInfos) ForItemType(v string) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		for _, loc := range a.Context.Locations {
			if strings.EqualFold(loc.ItemType, v) {
				return true
			}
		}
		return false
	})
}

func (d RuleValidationInfos) ForMessage(v interface{}) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		if rgx, ok := v.(*regexp.Regexp); ok {
			return rgx.MatchString(a.Message)
		}
		if str, ok := v.(string); ok {
			return a.Message == str
		}
		panic("argument must be string or *regexp.Regexp")
	})
}

func (d RuleValidationInfos) Count() int {
	return len(d)
}

func (t *TestOutput) hasOutputJSON() bool {
	for i := 0; i < len(t.opts.args)-1; i++ {
		if t.opts.args[i] == "-o" && t.opts.args[i+1] == "json_output=true" {
			return true
		}
	}
	return false
}

func (t *TestOutput) Err() error {
	return multierr.Append(t.opts.err, t.err)
}

func (t *TestOutput) DurationExceeded() bool {
	for _, err := range multierr.Errors(t.Err()) {
		if err == context.DeadlineExceeded {
			return true
		}
	}
	return false
}

func (t *TestOutput) ExitCode() int {
	for _, err := range multierr.Errors(t.Err()) {
		if exitCodeErr, ok := err.(*run.ExitCodeError); ok {
			return exitCodeErr.Code
		}
	}
	return 0
}

func (t *TestOutput) Stdout() string {
	return t.stdout.String()
}

func (t *TestOutput) Stderr() string {
	return t.stderr.String()
}

func (t *TestOutput) StdoutJSON() map[string]interface{} {
	res := make(map[string]interface{})
	if err := json.Unmarshal([]byte(t.Stdout()), &res); err != nil {
		logrus.Errorf("TestOutput.StdoutJSON: stdout is not json")
		return nil
	}
	return res
}

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
			// todo(jasondellaluce): consider logging this? it is quite noisy
			// logrus.WithField("line", line).Debugf("TestOutput.Detections: stdout line not JSON")
			continue
		}
		res = append(res, &alert)
	}
	return res
}

func (t *TestOutput) RuleValidation() *RuleValidation {
	if !t.hasOutputJSON() {
		logrus.Errorf("TestOutput.Detections: must use WithOutputJSON")
	}

	res := &RuleValidation{}
	if err := json.Unmarshal([]byte(t.Stdout()), res); err != nil {
		logrus.WithField("stdout", t.Stdout()).Errorf("TestOutput.RuleValidation: can't parse stdout JSON")
		return nil
	}
	return res
}
