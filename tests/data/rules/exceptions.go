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

package rules

import "github.com/falcosecurity/testing/pkg/run"

var ExceptionsAppendItemFieldsValuesLenMismatch = run.NewStringFileAccessor(
	"append_item_fields_values_len_mismatch.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [proc.name, fd.filename]
  priority: error

- rule: My Rule
  exceptions:
    - name: ex1
      values:
        - [nginx]
  append: true
`,
)

var ExceptionsAppendItemNoName = run.NewStringFileAccessor(
	"append_item_no_name.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [proc.name, fd.filename]
  priority: error

- rule: My Rule
  exceptions:
    - values:
        - [nginx, /tmp/foo]
  append: true
`,
)

var ExceptionsAppendItemNotInRule = run.NewStringFileAccessor(
	"append_item_not_in_rule.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [proc.name, fd.filename]
  priority: error

- rule: My Rule
  exceptions:
    - name: ex2
      values:
        - [apache, /tmp]
  append: true
`,
)

var ExceptionsItemCompsFieldsLenMismatch = run.NewStringFileAccessor(
	"item_comps_fields_len_mismatch.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [proc.name, fd.filename]
      comps: [=]
  priority: error
`,
)

var ExceptionsItemFieldsValuesLenMismatch = run.NewStringFileAccessor(
	"item_fields_values_len_mismatch.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [proc.name, fd.filename]
      values:
        - [nginx]
  priority: error
`,
)

var ExceptionsItemNoFields = run.NewStringFileAccessor(
	"item_no_fields.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
  priority: error
`,
)

var ExceptionsItemNoName = run.NewStringFileAccessor(
	"item_no_name.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - fields: [proc.name, fd.filename]
  priority: error
`,
)

var ExceptionsItemUnknownComp = run.NewStringFileAccessor(
	"item_unknown_comp.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [proc.name, fd.filename]
      comps: [=, no-comp]
  priority: error
`,
)

var ExceptionsItemUnknownFields = run.NewStringFileAccessor(
	"item_unknown_fields.yaml",
	`
- rule: My Rule
  desc: Some desc
  condition: evt.type=open and proc.name=cat
  output: Some output
  exceptions:
    - name: ex1
      fields: [not.exist]
  priority: error
`,
)

var ExceptionsRuleExceptionAppendComp = run.NewStringFileAccessor(
	"rule_exception_append_comp.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_contains
      fields: [proc.name]
      comps: [contains]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name_contains
      values:
        - [cat]
  append: true
`,
)

var ExceptionsRuleExceptionAppendMultiple = run.NewStringFileAccessor(
	"rule_exception_append_multiple.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name
      values:
        - [not-cat]
  append: true

- rule: Open From Cat
  exceptions:
    - name: proc_name
      values:
        - [cat]
  append: true
`,
)

var ExceptionsRuleExceptionAppendOneValue = run.NewStringFileAccessor(
	"rule_exception_append_one_value.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
      values:
        - [cat]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name
      values:
        - [cat]
  append: true`,
)

var ExceptionsRuleExceptionAppendSecondItem = run.NewStringFileAccessor(
	"rule_exception_append_second_item.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name
      values:
        - [not-cat]
    - name: proc_name_cmdline
      values:
        - [cat, "cat /dev/null"]
    - name: proc_name_cmdline_pname
      values:
        - [not-cat, "cat /dev/null", bash]
  append: true
`,
)

var ExceptionsRuleExceptionAppendSecondValue = run.NewStringFileAccessor(
	"rule_exception_append_second_value.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name_cmdline
      values:
        - [not-cat, not-cat]
        - [cat, "cat /dev/null"]
  append: true
`,
)

var ExceptionsRuleExceptionAppendThirdItem = run.NewStringFileAccessor(
	"rule_exception_append_third_item.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name
      values:
        - [not-cat]
    - name: proc_name_cmdline
      values:
        - [not-cat, "cat /dev/null"]
    - name: proc_name_cmdline_pname
      values:
        - [cat, "cat /dev/null", bash]
  append: true
`,
)

var ExceptionsRuleExceptionComp = run.NewStringFileAccessor(
	"rule_exception_comp.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_contains
      fields: [proc.name]
      comps: [contains]
      values:
        - [cat]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionNewNoFieldAppend = run.NewStringFileAccessor(
	"rule_exception_new_no_field_append.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_cmdline
      comps: in
      values:
        - "cat /dev/null"
  append: true
`,
)

var ExceptionsRuleExceptionNewSecondFieldAppend = run.NewStringFileAccessor(
	"rule_exception_new_second_field_append.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_cmdline
      fields: proc.cmdline
      comps: in
      values:
        - cat /dev/zero
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_cmdline_2
      fields: proc.cmdline
      comps: in
      values:
        - "cat /dev/null"
  append: true
`,
)

var ExceptionsRuleExceptionNewSingleFieldAppend = run.NewStringFileAccessor(
	"rule_exception_new_single_field_append.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_cmdline
      fields: proc.cmdline
      comps: in
      values:
        - "cat /dev/null"
  append: true
`,
)

var ExceptionsRuleExceptionNoValues = run.NewStringFileAccessor(
	"rule_exception_no_values.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionOneValue = run.NewStringFileAccessor(
	"rule_exception_one_value.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
      values:
        - [cat]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionQuoted = run.NewStringFileAccessor(
	"rule_exception_quoted.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_name_cmdline
      values:
        - [not-cat, not-cat]
        - [cat, '"cat /dev/null"']
  append: true
`,
)

var ExceptionsRuleExceptionSecondItem = run.NewStringFileAccessor(
	"rule_exception_second_item.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
      values:
        - [not-cat]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
      values:
        - [cat, "cat /dev/null"]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
      values:
        - [not-cat, "cat /dev/null", bash]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionSecondValue = run.NewStringFileAccessor(
	"rule_exception_second_value.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
      values:
        - [not-cat, not-cat]
        - [cat, "cat /dev/null"]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionSingleField = run.NewStringFileAccessor(
	"rule_exception_single_field.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_cmdline
      fields: proc.cmdline
      comps: in
      values:
        - cat /dev/zero
        - "cat /dev/null"
  priority: WARNING
`,
)

var ExceptionsRuleExceptionSingleFieldAppend = run.NewStringFileAccessor(
	"rule_exception_single_field_append.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_cmdline
      fields: proc.cmdline
      comps: in
      values:
        - cat /dev/zero
  priority: WARNING

- rule: Open From Cat
  exceptions:
    - name: proc_cmdline
      values:
        - "cat /dev/null"
  append: true
`,
)

var ExceptionsRuleExceptionThirdItem = run.NewStringFileAccessor(
	"rule_exception_third_item.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name
      fields: [proc.name]
      values:
        - [not-cat]
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
      values:
        - [not-cat, "cat /dev/null"]
    - name: proc_name_cmdline_pname
      fields: [proc.name, proc.cmdline, proc.pname]
      values:
        - [cat, "cat /dev/null", bash]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionValuesList = run.NewStringFileAccessor(
	"rule_exception_values_list.yaml",
	`
- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
      comps: [=, in]
      values:
        - [cat, [cat /dev/zero, "cat /dev/null"]]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionValuesListref = run.NewStringFileAccessor(
	"rule_exception_values_listref.yaml",
	`
- list: cat_cmdlines
  items: [cat /dev/zero, "cat /dev/null"]

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
      comps: [=, in]
      values:
        - [cat, (cat_cmdlines)]
  priority: WARNING
`,
)

var ExceptionsRuleExceptionValuesListrefNoparens = run.NewStringFileAccessor(
	"rule_exception_values_listref_noparens.yaml",
	`
- list: cat_cmdlines
  items: [cat /dev/zero, "cat /dev/null"]

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (command=%proc.cmdline)"
  exceptions:
    - name: proc_name_cmdline
      fields: [proc.name, proc.cmdline]
      comps: [=, in]
      values:
        - [cat, cat_cmdlines]
  priority: WARNING
`,
)
