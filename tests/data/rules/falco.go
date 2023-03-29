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

import (
	"github.com/falcosecurity/testing/pkg/run"
)

var FalcoRules = run.NewLocalFileAccessor(
	"falco_rules.yaml",
	"/etc/falco/falco_rules.yaml",
)

var AppendSingleRule = run.NewStringFileAccessor(
	"append_single_rule.yaml",
	`
- rule: open_from_cat
  append: true
  condition: and fd.name=/tmp
`,
)

var CatchallOrder = run.NewStringFileAccessor(
	"catchall_order.yaml",
	`
- rule: open_dev_null
  desc: Any open of the file /dev/null
  condition: evt.type=open and fd.name=/dev/null
  output: An open of /dev/null was seen (command=%proc.cmdline evt=%evt.type %evt.args)
  priority: INFO

- rule: dev_null
  desc: Anything related to /dev/null
  condition: fd.name=/dev/null
  output: Something related to /dev/null was seen (command=%proc.cmdline evt=%evt.type %evt.args)
  priority: INFO
  warn_evttypes: false
`,
)

var DetectConnectUsingIn = run.NewStringFileAccessor(
	"detect_connect_using_in.yaml",
	`
- rule: Localhost connect
  desc: Detect any connect to the localhost network, using fd.net and the in operator
  condition: evt.type=connect and fd.net in ("127.0.0.1/24")
  output: Program connected to localhost network
    (user=%user.name user_loginuid=%user.loginuid command=%proc.cmdline connection=%fd.name)
  priority: INFO
`,
)

var DisabledRuleUsingEnabledFlagOnly = run.NewStringFileAccessor(
	"disabled_rule_using_enabled_flag_only.yaml",
	`
- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen"
  priority: WARNING

- rule: open_from_cat
  enabled: false
`,
)

var DoubleRule = run.NewStringFileAccessor(
	"double_rule.yaml",
	`
# This ruleset depends on the is_cat macro defined in single_rule.yaml

- rule: exec_from_cat
  desc: A process named cat does execve
  condition: evt.type=execve and is_cat
  output: "An exec was seen (command=%proc.cmdline)"
  priority: ERROR

- rule: access_from_cat
  desc: A process named cat does an access
  condition: evt.type=access and is_cat
  output: "An access was seen (command=%proc.cmdline)"
  priority: INFO
`,
)

var EmptyRules = run.NewStringFileAccessor(
	"empty_rules.yaml",
	`
`,
)

var EnabledRuleUsingEnabledFlagOnly = run.NewStringFileAccessor(
	"enabled_rule_using_enabled_flag_only.yaml",
	`
- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen"
  priority: WARNING
  enabled: false

- rule: open_from_cat
  enabled: true
`,
)

var Endswith = run.NewStringFileAccessor(
	"endswith.yaml",
	`
- rule: open_ending with null
  desc: A file ending with null is opened
  condition: evt.type=open and fd.name endswith null
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var EngineVersionMismatch = run.NewStringFileAccessor(
	"engine_version_mismatch.yaml",
	`
- required_engine_version: 9999999

- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var FalcoRulesWarnings = run.NewStringFileAccessor(
	"falco_rules_warnings.yaml",
	`
- rule: no_warnings
  desc: Rule with no warnings
  condition: evt.type=execve
  output: "None"
  priority: WARNING

- rule: no_evttype
  desc: No evttype at all
  condition: proc.name=foo
  output: "None"
  priority: WARNING

- rule: evttype_not_equals
  desc: Using != for event type
  condition: evt.type!=execve
  output: "None"
  priority: WARNING

- rule: leading_not
  desc: condition starts with not
  condition: not evt.type=execve
  output: "None"
  priority: WARNING

- rule: not_equals_after_evttype
  desc: != after evt.type, not affecting results
  condition: evt.type=execve and proc.name!=foo
  output: "None"
  priority: WARNING

- rule: not_after_evttype
  desc: not operator after evt.type, not affecting results
  condition: evt.type=execve and not proc.name=foo
  output: "None"
  priority: WARNING

- rule: leading_trailing_evttypes
  desc: evttype at beginning and end
  condition: evt.type=execve and proc.name=foo or evt.type=open
  output: "None"
  priority: WARNING

- rule: leading_multitrailing_evttypes
  desc: one evttype at beginning, multiple at end
  condition: evt.type=execve and proc.name=foo or evt.type=open or evt.type=connect
  output: "None"
  priority: WARNING

- rule: leading_multitrailing_evttypes_using_in
  desc: one evttype at beginning, multiple at end, using in
  condition: evt.type=execve and proc.name=foo or evt.type in (open, connect)
  output: "None"
  priority: WARNING

- rule: not_equals_at_end
  desc: not_equals at final evttype
  condition: evt.type=execve and proc.name=foo or evt.type=open or evt.type!=connect
  output: "None"
  priority: WARNING

- rule: not_at_end
  desc: not operator for final evttype
  condition: evt.type=execve and proc.name=foo or evt.type=open or not evt.type=connect
  output: "None"
  priority: WARNING

- rule: not_before_trailing_evttype
  desc: a not before a trailing event type
  condition: evt.type=execve and not proc.name=foo or evt.type=open
  output: "None"
  priority: WARNING

- rule: not_equals_before_trailing_evttype
  desc: a != before a trailing event type
  condition: evt.type=execve and proc.name!=foo or evt.type=open
  output: "None"
  priority: WARNING

- rule: not_equals_and_not
  desc: both != and not before event types
  condition: evt.type=execve and proc.name!=foo or evt.type=open or not evt.type=connect
  output: "None"
  priority: WARNING

- rule: not_equals_before_in
  desc: != before an in with event types
  condition: evt.type=execve and proc.name!=foo or evt.type in (open, connect)
  output: "None"
  priority: WARNING

- rule: not_before_in
  desc: a not before an in with event types
  condition: evt.type=execve and not proc.name=foo or evt.type in (open, connect)
  output: "None"
  priority: WARNING

- rule: not_in_before_in
  desc: a not with in before an in with event types
  condition: evt.type=execve and not proc.name in (foo, bar) or evt.type in (open, connect)
  output: "None"
  priority: WARNING

- rule: evttype_in
  desc: using in for event types
  condition: evt.type in (execve, open)
  output: "None"
  priority: WARNING

- rule: evttype_in_plus_trailing
  desc: using in for event types and a trailing evttype
  condition: evt.type in (execve, open) and proc.name=foo or evt.type=connect
  output: "None"
  priority: WARNING

- rule: leading_in_not_equals_before_evttype
  desc: initial in() for event types, then a != before an additional event type
  condition: evt.type in (execve, open) and proc.name!=foo or evt.type=connect
  output: "None"
  priority: WARNING

- rule: leading_in_not_equals_at_evttype
  desc: initial in() for event types, then a != with an additional event type
  condition: evt.type in (execve, open) or evt.type!=connect
  output: "None"
  priority: WARNING

- rule: not_with_evttypes
  desc: not in for event types
  condition: not evt.type in (execve, open)
  output: "None"
  priority: WARNING

- rule: not_with_evttypes_addl
  desc: not in for event types, and an additional event type
  condition: not evt.type in (execve, open) or evt.type=connect
  output: "None"
  priority: WARNING

- rule: not_equals_before_evttype
  desc: != before any event type
  condition: proc.name!=foo and evt.type=execve
  output: "None"
  priority: WARNING

- rule: not_equals_before_in_evttype
  desc: != before any event type using in
  condition: proc.name!=foo and evt.type in (execve, open)
  output: "None"
  priority: WARNING

- rule: not_before_evttype
  desc: not operator before any event type
  condition: not proc.name=foo and evt.type=execve
  output: "None"
  priority: WARNING

- rule: not_before_evttype_using_in
  desc: not operator before any event type using in
  condition: not proc.name=foo and evt.type in (execve, open)
  output: "None"
  priority: WARNING

- rule: repeated_evttypes
  desc: event types appearing multiple times
  condition: evt.type=open or evt.type=open
  output: "None"
  priority: WARNING

- rule: repeated_evttypes_with_in
  desc: event types appearing multiple times with in
  condition: evt.type in (open, open)
  output: "None"
  priority: WARNING

- rule: repeated_evttypes_with_separate_in
  desc: event types appearing multiple times with separate ins
  condition: evt.type in (open) or evt.type in (open, open)
  output: "None"
  priority: WARNING

- rule: repeated_evttypes_with_mix
  desc: event types appearing multiple times with mix of = and in
  condition: evt.type=open or evt.type in (open, open)
  output: "None"
  priority: WARNING
`,
)

var InvalidAppendMacro = run.NewStringFileAccessor(
	"invalid_append_macro.yaml",
	`- macro: some macro
  condition: foo
  append: true
`,
)

var InvalidAppendMacroDangling = run.NewStringFileAccessor(
	"invalid_append_macro_dangling.yaml",
	`- macro: dangling append
  condition: and evt.type=execve
  append: true`,
)

var InvalidAppendMacroMultipleDocs = run.NewStringFileAccessor(
	"invalid_append_macro_multiple_docs.yaml",
	`---
- macro: some macro
  condition: evt.type=execve
---
- macro: some macro
  condition: foo
  append: true
`,
)

var InvalidAppendRule = run.NewStringFileAccessor(
	"invalid_append_rule.yaml",
	`- rule: some rule
  desc: some desc
  condition: bar
  output: some output
  priority: INFO
  append: true`,
)

var InvalidAppendRuleMultipleDocs = run.NewStringFileAccessor(
	"invalid_append_rule_multiple_docs.yaml",
	`---
- rule: some rule
  desc: some desc
  condition: evt.type=open
  output: some output
  priority: INFO
---
- rule: some rule
  desc: some desc
  condition: bar
  output: some output
  priority: INFO
  append: true`,
)

var InvalidAppendRuleWithoutCondition = run.NewStringFileAccessor(
	"invalid_append_rule_without_condition.yaml",
	`
- rule: no condition rule
  desc: simpe rule 
  condition: evt.type=open
  output: simple output
  priority: WARNING

- rule: no condition rule
  append: true`,
)

var InvalidArrayItemNotObject = run.NewStringFileAccessor(
	"invalid_array_item_not_object.yaml",
	`- foo
`,
)

var InvalidBaseMacro = run.NewStringFileAccessor(
	"invalid_base_macro.yaml",
	`- macro: some macro
  condition: evt.type=execve
`,
)

var InvalidBaseRule = run.NewStringFileAccessor(
	"invalid_base_rule.yaml",
	`- rule: some rule
  desc: some desc
  condition: evt.type=open
  output: some output
  priority: INFO`,
)

var InvalidConditionNotRule = run.NewStringFileAccessor(
	"invalid_condition_not_rule.yaml",
	`- rule: condition not rule
  condition:
  desc: some desc
  output: some output
  priority: INFO
`,
)

var InvalidEngineVersionNotNumber = run.NewStringFileAccessor(
	"invalid_engine_version_not_number.yaml",
	`
- required_engine_version: not-a-number

- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var InvalidListLoop = run.NewStringFileAccessor(
	"invalid_list_loop.yaml",
	`- list: list_a
  items: [open]

- list: list_b
  items: [list_a]

- list: list_a
  items: [list_b]

- macro: macro_a
  condition: evt.type in (list_a)

- rule: sample rule
  priority: WARNING
  output: test
  desc: testdesc
  condition: macro_a`,
)

var InvalidListWithoutItems = run.NewStringFileAccessor(
	"invalid_list_without_items.yaml",
	`- list: good_list
  items: [foo]

- list: bad_list
  no_items: foo`,
)

var InvalidMacroCompleError = run.NewStringFileAccessor(
	"invalid_macro_comple_error.yaml",
	`- macro: macro with comp error
  condition: gak
`,
)

var InvalidMacroLoop = run.NewStringFileAccessor(
	"invalid_macro_loop.yaml",
	`- macro: macro_a
  condition: evt.type=open

- macro: macro_b
  condition: macro_a

- macro: macro_a
  condition: macro_b
`,
)

var InvalidMacroWithoutCondition = run.NewStringFileAccessor(
	"invalid_macro_without_condition.yaml",
	`- macro: bad_macro
  nope: 1

- macro: good_macro
  condition: evt.type=execve
`,
)

var InvalidMissingListName = run.NewStringFileAccessor(
	"invalid_missing_list_name.yaml",
	`- list:
  items: [foo]`,
)

var InvalidMissingMacroName = run.NewStringFileAccessor(
	"invalid_missing_macro_name.yaml",
	`- macro:
  condition: evt.type=execve
`,
)

var InvalidMissingRuleName = run.NewStringFileAccessor(
	"invalid_missing_rule_name.yaml",
	`- rule:
  desc: some desc
  condition: evt.type=execve
  output: some output
`,
)

var InvalidNotArray = run.NewStringFileAccessor(
	"invalid_not_array.yaml",
	`foo: bar`,
)

var InvalidNotYaml = run.NewStringFileAccessor(
	"invalid_not_yaml.yaml",
	`This is not yaml`,
)

var InvalidOverwriteMacro = run.NewStringFileAccessor(
	"invalid_overwrite_macro.yaml",
	`- macro: some macro
  condition: foo
  append: false
`,
)

var InvalidOverwriteMacroMultipleDocs = run.NewStringFileAccessor(
	"invalid_overwrite_macro_multiple_docs.yaml",
	`---
- macro: some macro
  condition: evt.type=execve
---
- macro: some macro
  condition: foo
  append: false
`,
)

var InvalidOverwriteRule = run.NewStringFileAccessor(
	"invalid_overwrite_rule.yaml",
	`- rule: some rule
  desc: some desc
  condition: bar
  output: some output
  priority: INFO
  append: false`,
)

var InvalidOverwriteRuleMultipleDocs = run.NewStringFileAccessor(
	"invalid_overwrite_rule_multiple_docs.yaml",
	`---
- rule: some rule
  desc: some desc
  condition: evt.type=open
  output: some output
  priority: INFO
---
- rule: some rule
  desc: some desc
  condition: bar
  output: some output
  priority: INFO
  append: false`,
)

var InvalidRuleOutput = run.NewStringFileAccessor(
	"invalid_rule_output.yaml",
	`
- rule: rule_with_invalid_output
  desc: A rule with an invalid output field
  condition: evt.type=open
  output: "An open was seen %not_a_real_field"
  priority: WARNING
`,
)

var InvalidRuleWithoutOutput = run.NewStringFileAccessor(
	"invalid_rule_without_output.yaml",
	`- rule: no output rule
  desc: some desc
  condition: evt.type=fork
  priority: INFO
`,
)

var InvalidYamlParseError = run.NewStringFileAccessor(
	"invalid_yaml_parse_error.yaml",
	`this : is : not : yaml`,
)

var ListAppend = run.NewStringFileAccessor(
	"list_append.yaml",
	`
- list: my_list
  items: [not-cat]

- list: my_list
  append: true
  items: [cat]

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name in (my_list)
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListAppendFailure = run.NewStringFileAccessor(
	"list_append_failure.yaml",
	`
- list: my_list
  items: [not-cat]
  append: true
`,
)

var ListAppendFalse = run.NewStringFileAccessor(
	"list_append_false.yaml",
	`
- list: my_list
  items: [cat]

- list: my_list
  append: false
  items: [not-cat]

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name in (my_list)
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListOrder = run.NewStringFileAccessor(
	"list_order.yaml",
	`
- list: cat_binaries
  items: [not_cat]

- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name in (cat_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListSubBare = run.NewStringFileAccessor(
	"list_sub_bare.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name=cat_binaries

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListSubEnd = run.NewStringFileAccessor(
	"list_sub_end.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name in (ls, cat_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListSubFront = run.NewStringFileAccessor(
	"list_sub_front.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name in (cat_binaries, ps)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListSubMid = run.NewStringFileAccessor(
	"list_sub_mid.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name in (ls, cat_binaries, ps)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListSubWhitespace = run.NewStringFileAccessor(
	"list_sub_whitespace.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name= cat_binaries or proc.name=nopey

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var ListSubstring = run.NewStringFileAccessor(
	"list_substring.yaml",
	`
- list: my_list
  items: ['"one string"']

- rule: my_rule
  desc: my description
  condition: evt.type=open and fd.name in (file_my_list)
  output: my output
  priority: INFO
`,
)

var MacroAppend = run.NewStringFileAccessor(
	"macro_append.yaml",
	`
- macro: my_macro
  condition: proc.name=not-cat

- macro: my_macro
  append: true
  condition: or proc.name=cat

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and my_macro
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var MacroAppendFalse = run.NewStringFileAccessor(
	"macro_append_false.yaml",
	`
- macro: my_macro
  condition: proc.name=cat

- macro: my_macro
  append: false
  condition: proc.name=not-cat

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and my_macro
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var MacroOrder = run.NewStringFileAccessor(
	"macro_order.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name in (not_cat)

- macro: is_cat
  condition: proc.name in (cat_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var MultipleDocs = run.NewStringFileAccessor(
	"multiple_docs.yaml",
	`---
- required_engine_version: 2

- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING

---
# This ruleset depends on the is_cat macro defined in single_rule.yaml

- rule: exec_from_cat
  desc: A process named cat does execve
  condition: evt.type=execve and is_cat
  output: "An exec was seen (command=%proc.cmdline)"
  priority: ERROR

- rule: access_from_cat
  desc: A process named cat does an access
  condition: evt.type=access and is_cat
  output: "An access was seen (command=%proc.cmdline)"
  priority: INFO
`,
)

var NullOutputField = run.NewStringFileAccessor(
	"null_output_field.yaml",
	`
- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=cat
  output: "An open was seen (cport=%fd.cport command=%proc.cmdline)"
  priority: WARNING
`,
)

var OverrideList = run.NewStringFileAccessor(
	"override_list.yaml",
	`
- list: cat_capable_binaries
  items: [not-cat]
`,
)

var OverrideMacro = run.NewStringFileAccessor(
	"override_macro.yaml",
	`
- macro: is_cat
  condition: proc.name in (not-cat)
`,
)

var OverrideNestedList = run.NewStringFileAccessor(
	"override_nested_list.yaml",
	`
- list: cat_binaries
  items: [not-cat]
`,
)

var OverrideRule = run.NewStringFileAccessor(
	"override_rule.yaml",
	`
- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=not-cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var PluginsCloudtrailCreateInstances = run.NewStringFileAccessor(
	"cloudtrail_create_instances.yaml",
	`- rule: Cloudtrail Create Instance
  desc: Detect Creating an EC2 Instance
  condition: evt.num > 0 and ct.name="StartInstances"
  output: EC2 Instance Created (evtnum=%evt.num info=%evt.plugininfo id=%ct.id user name=%json.value[/userIdentity/userName])
  priority: INFO
  source: aws_cloudtrail
`,
)

var PluginsCloudtrailCreateInstancesExceptions = run.NewStringFileAccessor(
	"cloudtrail_create_instances_exceptions.yaml",
	`- rule: Cloudtrail Create Instance
  desc: Detect Creating an EC2 Instance
  condition: evt.num > 0 and ct.name="StartInstances"
  output: EC2 Instance Created (evtnum=%evt.num info=%evt.plugininfo id=%ct.id user name=%json.value[/userIdentity/userName])
  exceptions:
  - name: user_secreid
    fields: [aws.user, aws.region]
  priority: INFO
  source: aws_cloudtrail
`,
)

var PluginsCloudtrailIncompatPluginVersion = run.NewStringFileAccessor(
	"cloudtrail_incompat_plugin_version.yaml",
	`- required_plugin_versions:
    - name: cloudtrail
      version: 100000.0.0

- rule: Cloudtrail Create Instance
  desc: Detect Creating an EC2 Instance
  condition: evt.num > 0 and ct.name="StartInstances"
  output: EC2 Instance Created (evtnum=%evt.num info=%evt.plugininfo id=%ct.id user name=%json.value[/userIdentity/userName])
  priority: INFO
  source: aws_cloudtrail
`,
)

var RuleAppend = run.NewStringFileAccessor(
	"rule_append.yaml",
	`
- rule: my_rule
  desc: A process named cat does an open
  condition: (evt.type=open and fd.name=not-a-real-file)
  output: "An open of /dev/null was seen (command=%proc.cmdline)"
  priority: WARNING

- rule: my_rule
  append: true
  condition: or (evt.type=open and fd.name=/dev/null)
`,
)

var RuleAppendFailure = run.NewStringFileAccessor(
	"rule_append_failure.yaml",
	`
- rule: my_rule
  condition: evt.type=open
  append: true
`,
)

var RuleAppendFalse = run.NewStringFileAccessor(
	"rule_append_false.yaml",
	`
- rule: my_rule
  desc: A process named cat does an open
  condition: evt.type=open and fd.name=/dev/null
  output: "An open of /dev/null was seen (command=%proc.cmdline)"
  priority: WARNING

- rule: my_rule
  append: true
  condition: and fd.name=not-a-real-file
`,
)

var RuleNamesWithRegexChars = run.NewStringFileAccessor(
	"rule_names_with_regex_chars.yaml",
	`
- macro: is_cat
  condition: proc.name=cat

- rule: Open From Cat ($\.*+?()[]{}|^)
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var RuleNamesWithSpaces = run.NewStringFileAccessor(
	"rule_names_with_spaces.yaml",
	`
- macro: is_cat
  condition: proc.name=cat

- rule: Open From Cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var RuleOrder = run.NewStringFileAccessor(
	"rule_order.yaml",
	`
- list: cat_binaries
  items: [cat]

- macro: is_cat
  condition: proc.name in (cat_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and proc.name=not_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var RulesDir000SingleRule = run.NewStringFileAccessor(
	"000-single_rule.yaml",
	`
- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var RulesDir001DoubleRule = run.NewStringFileAccessor(
	"001-double_rule.yaml",
	`
# This ruleset depends on the is_cat macro defined in single_rule.yaml

- rule: exec_from_cat
  desc: A process named cat does execve
  condition: evt.type=execve and is_cat
  output: "An exec was seen (command=%proc.cmdline)"
  priority: ERROR

- rule: access_from_cat
  desc: A process named cat does an access
  condition: evt.type=access and is_cat
  output: "An access was seen (command=%proc.cmdline)"
  priority: INFO
`,
)

var SingleRule = run.NewStringFileAccessor(
	"single_rule.yaml",
	`
- required_engine_version: 2

- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
`,
)

var SingleRuleEnabledFlag = run.NewStringFileAccessor(
	"single_rule_enabled_flag.yaml",
	`
- macro: is_cat
  condition: proc.name=cat

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
  enabled: false
`,
)

var SingleRuleWithTags = run.NewStringFileAccessor(
	"single_rule_with_tags.yaml",
	`
- required_engine_version: 2

- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING
  tags: [filesystem, process, testing]
`,
)

var SkipUnknownError = run.NewStringFileAccessor(
	"skip_unknown_error.yaml",
	`
- rule: Contains Unknown Event And Not Skipping
  desc: Contains an unknown event
  condition: proc.nobody=cat
  output: Never
  skip-if-unknown-filter: false
  priority: INFO
`,
)

var SkipUnknownEvt = run.NewStringFileAccessor(
	"skip_unknown_evt.yaml",
	`
- rule: Contains Unknown Event And Skipping
  desc: Contains an unknown event
  condition: evt.type=open and proc.nobody=cat
  output: Never
  skip-if-unknown-filter: true
  priority: INFO
`,
)

var SkipUnknownPrefix = run.NewStringFileAccessor(
	"skip_unknown_prefix.yaml",
	`
- rule: Contains Prefix of Filter
  desc: Testing matching filter prefixes
  condition: >
    evt.type=open and evt.arg.path="foo" and evt.arg[0]="foo"
    and proc.aname="ls" and proc.aname[1]="ls"
    and proc.apid=10 and proc.apid[1]=10
  output: Never
  priority: INFO
`,
)

var SkipUnknownUnspec = run.NewStringFileAccessor(
	"skip_unknown_unspec.yaml",
	`
- rule: Contains Unknown Event And Unspecified
  desc: Contains an unknown event
  condition: proc.nobody=cat
  output: Never
  priority: INFO
`,
)

var Syscalls = run.NewStringFileAccessor(
	"syscalls.yaml",
	`
- rule: detect_madvise
  desc: Detect any call to madvise
  condition: evt.type=madvise and evt.dir=<
  output: A madvise syscall was seen (command=%proc.cmdline evt=%evt.type)
  priority: INFO

- rule: detect_open
  desc: Detect any call to open
  condition: evt.type=open and evt.dir=< and fd.name=/dev/null
  output: An open syscall was seen (command=%proc.cmdline evt=%evt.type file=%fd.name)
  priority: INFO
`,
)

var TaggedRules = run.NewStringFileAccessor(
	"tagged_rules.yaml",
	`
- macro: open_read
  condition: evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f'

- rule: open_1
  desc: open one
  condition: open_read and fd.name=/tmp/file-1
  output: Open one (file=%fd.name)
  priority: WARNING
  tags: [a]

- rule: open_2
  desc: open two
  condition: open_read and fd.name=/tmp/file-2
  output: Open two (file=%fd.name)
  priority: WARNING
  tags: [b]

- rule: open_3
  desc: open three
  condition: open_read and fd.name=/tmp/file-3
  output: Open three (file=%fd.name)
  priority: WARNING
  tags: [c]

- rule: open_4
  desc: open four
  condition: open_read and fd.name=/tmp/file-4
  output: Open four (file=%fd.name)
  priority: WARNING
  tags: [a, b]

- rule: open_5
  desc: open file
  condition: open_read and fd.name=/tmp/file-5
  output: Open file (file=%fd.name)
  priority: WARNING
  tags: [a, c]

- rule: open_6
  desc: open six
  condition: open_read and fd.name=/tmp/file-6
  output: Open six (file=%fd.name)
  priority: WARNING
  tags: [b, c]

- rule: open_7
  desc: open seven
  condition: open_read and fd.name=/tmp/file-7
  output: Open seven (file=%fd.name)
  priority: WARNING
  tags: [a, b, c]

- rule: open_8
  desc: open eight
  condition: open_read and fd.name=/tmp/file-8
  output: Open eight (file=%fd.name)
  priority: WARNING
  tags: [b, a]

- rule: open_9
  desc: open nine
  condition: open_read and fd.name=/tmp/file-9
  output: Open nine (file=%fd.name)
  priority: WARNING
  tags: [c, a]

- rule: open_10
  desc: open ten
  condition: open_read and fd.name=/tmp/file-10
  output: Open ten (file=%fd.name)
  priority: WARNING
  tags: [b, c, a]

- rule: open_11
  desc: open eleven
  condition: open_read and fd.name=/tmp/file-11
  output: Open eleven (file=%fd.name)
  priority: WARNING
  tags: [d]

- rule: open_12
  desc: open twelve
  condition: open_read and fd.name=/tmp/file-12
  output: Open twelve (file=%fd.name)
  priority: WARNING
  tags: []

- rule: open_13
  desc: open thirteen
  condition: open_read and fd.name=/tmp/file-13
  output: Open thirteen (file=%fd.name)
  priority: WARNING
`,
)
