package falco

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

var emptyRuleValidationResult = RuleValidationResult{}

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

type RuleValidation struct {
	Results []*RuleValidationResult `json:"falco_load_results"`
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
