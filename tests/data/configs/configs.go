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

package configs

import (
	"github.com/falcosecurity/testing/pkg/run"
)

var EmptyConfig = run.NewStringFileAccessor("empty_config.yaml", "")

var DropsAlert = run.NewStringFileAccessor(
	"drops_alert.yaml",
	`
syscall_event_drops:
  actions:
    - alert
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true
`,
)

var DropsExit = run.NewStringFileAccessor(
	"drops_exit.yaml",
	`
syscall_event_drops:
  actions:
    - exit
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true
`,
)

var DropsIgnore = run.NewStringFileAccessor(
	"drops_ignore.yaml",
	`
syscall_event_drops:
  actions:
    - ignore
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true
`,
)

var DropsIgnoreLog = run.NewStringFileAccessor(
	"drops_ignore_log.yaml",
	`
syscall_event_drops:
  actions:
    - ignore
    - log
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true
`,
)

var DropsLog = run.NewStringFileAccessor(
	"drops_log.yaml",
	`
syscall_event_drops:
  actions:
    - log
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true

log_level: debug
`,
)

var DropsNone = run.NewStringFileAccessor(
	"drops_none.yaml",
	`
syscall_event_drops:
  actions:
    - log
  rate: .03333
  max_burst: 10
  simulate_drops: false

stdout_output:
  enabled: true

log_stderr: true
`,
)

var DropsThresholdNeg = run.NewStringFileAccessor(
	"drops_threshold_neg.yaml",
	`
syscall_event_drops:
  threshold: -1
  actions:
    - ignore
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true
`,
)

var DropsThresholdOor = run.NewStringFileAccessor(
	"drops_threshold_oor.yaml",
	`
syscall_event_drops:
  threshold: 1.1
  actions:
    - ignore
  rate: .03333
  max_burst: 10
  simulate_drops: true

stdout_output:
  enabled: true

log_stderr: true
`,
)

var FileOutput = run.NewStringFileAccessor(
	"file_output.yaml",
	`
# File containing Falco rules, loaded at startup.
rules_file: /etc/falco_rules.yaml

# Whether to output events in json or text
json_output: false

# Send information logs to stderr and/or syslog Note these are *not* security
# notification logs! These are just Falco lifecycle (and possibly error) logs.
log_stderr: false
log_syslog: false

# Where security notifications should go.
# Multiple outputs can be enabled.

syslog_output:
  enabled: false

file_output:
  enabled: true
  filename: /tmp/falco_outputs/file_output.txt

stdout_output:
  enabled: true

program_output:
  enabled: false
  program: mail -s "Falco Notification" someone@example.com
`,
)

var GrpcUnixSocket = run.NewStringFileAccessor(
	"grpc_unix_socket.yaml",
	`
# Whether to output events in json or text.
json_output: false

# Send information logs to stderr and/or syslog
# Note these are *not* security notification logs!
# These are just Falco lifecycle (and possibly error) logs.
log_stderr: false
log_syslog: false

# Where security notifications should go.
stdout_output:
  enabled: false

# gRPC server using an unix socket.
grpc:
    enabled: true
    bind_address: "unix:///tmp/falco/falco.sock"
    threadiness: 8

grpc_output:
  enabled: true`,
)

var PluginsCloudtrailJsonCreateInstances = run.NewStringFileAccessor(
	"cloudtrail_json_create_instances.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: cloudtrail
    library_path: BUILD_DIR/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so
    init_config: ""
    open_params: "BUILD_DIR/test/trace_files/plugins/alice_start_instances.json"
  - name: json
    library_path: BUILD_DIR/json-plugin-prefix/src/json-plugin/libjson.so
    init_config: ""

# Optional
load_plugins: [cloudtrail, json]
`,
)

var PluginsCloudtrailJsonCreateInstancesBigevent = run.NewStringFileAccessor(
	"cloudtrail_json_create_instances_bigevent.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: cloudtrail
    library_path: BUILD_DIR/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so
    init_config: ""
    open_params: "BUILD_DIR/test/trace_files/plugins/alice_start_instances_bigevent.json"
  - name: json
    library_path: BUILD_DIR/json-plugin-prefix/src/json-plugin/libjson.so
    init_config: ""

# Optional
load_plugins: [cloudtrail, json]
`,
)

var PluginsIncompatibleExtractSources = run.NewStringFileAccessor(
	"incompatible_extract_sources.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: cloudtrail
    library_path: BUILD_DIR/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so
    init_config: ""
    open_params: ""
  - name: test_extract_p1
    library_path: BUILD_DIR/test/plugins/libtest_extract_p1.so
    init_config: ""

# Optional
load_plugins: [cloudtrail, test_extract_p1]
`,
)

var PluginsIncompatiblePluginApi = run.NewStringFileAccessor(
	"incompatible_plugin_api.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: incompatible_plugin_api
    library_path: BUILD_DIR/test/plugins/libtest_incompat_api.so
    init_config: ""

# Optional
load_plugins: [incompatible_plugin_api]
`,
)

var PluginsK8SAudit = run.NewStringFileAccessor(
	"k8s_audit.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: k8saudit
    library_path: BUILD_DIR/k8saudit-plugin-prefix/src/k8saudit-plugin/libk8saudit.so
    init_config: ""
    open_params: "" # to be filled out by each test case
  - name: json
    library_path: BUILD_DIR/json-plugin-prefix/src/json-plugin/libjson.so
    init_config: ""

load_plugins: [k8saudit, json]
`,
)

var PluginsOverlapExtractSources = run.NewStringFileAccessor(
	"overlap_extract_sources.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: test_source
    library_path: BUILD_DIR/test/plugins/libtest_source.so
    init_config: ""
    open_params: ""
  - name: test_extract_p1
    library_path: BUILD_DIR/test/plugins/libtest_extract_p1.so
    init_config: ""
  - name: test_extract_p2
    library_path: BUILD_DIR/test/plugins/libtest_extract_p2.so
    init_config: ""

# Optional
load_plugins: [test_source, test_extract_p1, test_extract_p2]
`,
)

var PluginsWrongPluginPath = run.NewStringFileAccessor(
	"wrong_plugin_path.yaml",
	`
stdout_output:
  enabled: true

plugins:
  - name: wrong_plugin_path
    library_path: BUILD_DIR/test/plugins/wrong_plugin_path.so
    init_config: ""

# Optional
load_plugins: [wrong_plugin_path]
`,
)

var ProgramOutput = run.NewStringFileAccessor(
	"program_output.yaml",
	`
# File containing Falco rules, loaded at startup.
rules_file: /etc/falco_rules.yaml

# Whether to output events in json or text
json_output: false

# Send information logs to stderr and/or syslog
# Note these are *not* security notification logs!
# These are just Falco lifecycle (and possibly error) logs.
log_stderr: false
log_syslog: false

# Where security notifications should go.
# Multiple outputs can be enabled.
syslog_output:
  enabled: false

file_output:
  enabled: false
  filename: ./output.txt

stdout_output:
  enabled: true

program_output:
  enabled: true
  program: cat >> /tmp/falco_outputs/program_output.txt
`,
)

var StdoutOutput = run.NewStringFileAccessor(
	"stdout_output.yaml",
	`
# File containing Falco rules, loaded at startup.
rules_file: /etc/falco_rules.yaml

# Whether to output events in json or text
json_output: false

# Send information logs to stderr and/or syslog Note these are *not* security
# notification logs! These are just Falco lifecycle (and possibly error) logs.
log_stderr: false
log_syslog: false

# Where security notifications should go.
# Multiple outputs can be enabled.

syslog_output:
  enabled: false

file_output:
  enabled: false

stdout_output:
  enabled: true

program_output:
  enabled: false
`,
)

var RuleMatchingFirst = run.NewStringFileAccessor(
	"rule_matching_first.yaml",
	`
rule_matching: first
  `,
)

var RuleMatchingAll = run.NewStringFileAccessor(
	"rule_matching_all.yaml",
	`
rule_matching: all
  `,
)

var RuleMatchingWrongValue = run.NewStringFileAccessor(
	"rule_matching_wrong_value.yaml",
	`
rule_matching: test
  `,
)
