package falco

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

var emptyRuleValidationResult = RuleValidationResult{}

// RuleValidationInfo represent a single error or warning resulting from
// the validation of a Falco rules file.
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

// RuleValidationInfos represent group of errors or warnings resulting from
// the validation of a Falco rules file.
type RuleValidationInfos []*RuleValidationInfo

// RuleValidationResult represents the validation result of a Falco rules file.
type RuleValidationResult struct {
	Successful bool                `json:"successful"`
	Name       string              `json:"name"`
	Errors     RuleValidationInfos `json:"errors"`
	Warnings   RuleValidationInfos `json:"warnings"`
}

// RuleValidation represents a list of validation results of Falco rules files.
type RuleValidation struct {
	Results []*RuleValidationResult `json:"falco_load_results"`
}

// RuleValidation converts the output of the Falco run into a list of
// validation results of Falco rules files. Returns nil if Falco wasn't run
// for rules files validation.
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

// At returns the validation result at the given index in the set.
// Returns an empty validation result if the index is out of bounds.
// todo(jasondellaluce): should we panic/fatal in this case?
func (r RuleValidation) At(index int) *RuleValidationResult {
	if index >= len(r.Results) {
		return &emptyRuleValidationResult
	}
	return r.Results[index]
}

// AllWarnings returns the merged list of warnings from all the validated Falco rules files.
func (r RuleValidation) AllWarnings() RuleValidationInfos {
	var res RuleValidationInfos
	for _, result := range r.Results {
		res = append(res, result.Warnings...)
	}
	return res
}

// AllErrors returns the merged list of errors from all the validated Falco rules files.
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

// OfCode returns the validation info entries with the given code.
func (d RuleValidationInfos) OfCode(v string) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		return strings.EqualFold(a.Code, v)
	})
}

// OfItemName returns the validation info entries with the given item name.
func (d RuleValidationInfos) OfItemName(v string) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		for _, loc := range a.Context.Locations {
			if loc.ItemName == v {
				return true
			}
		}
		return false
	})
}

// OfItemType returns the validation info entries with the given item type.
func (d RuleValidationInfos) OfItemType(v string) RuleValidationInfos {
	return d.filter(func(a *RuleValidationInfo) bool {
		for _, loc := range a.Context.Locations {
			if strings.EqualFold(loc.ItemType, v) {
				return true
			}
		}
		return false
	})
}

// OfMessage returns the validation info entries with the given message.
// The message can either be a string or a *regexp.Regexp.
func (d RuleValidationInfos) OfMessage(v interface{}) RuleValidationInfos {
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

// Count returns the amount of validation infos in the list.
func (d RuleValidationInfos) Count() int {
	return len(d)
}
