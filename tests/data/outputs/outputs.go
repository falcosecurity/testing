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

package outputs

import "github.com/falcosecurity/testing/pkg/run"

var SingleRuleWithCatWriteText = run.NewStringFileAccessor(
	"single_rule_with_cat_write.txt",
	`2016-08-04T16:17:57.881781397+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.881785348+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.881796705+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.881799840+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.882003104+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.882008208+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.882045694+0000: Warning An open was seen (command=cat /dev/null)
2016-08-04T16:17:57.882054739+0000: Warning An open was seen (command=cat /dev/null)
`)

var SingleRuleWithCatWriteJSON = run.NewStringFileAccessor(
	"single_rule_with_cat_write.json",
	`{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.881781397+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.881781397Z", "output_fields": {"evt.time.iso8601":1470327477881781397,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.881785348+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.881785348Z", "output_fields": {"evt.time.iso8601":1470327477881785348,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.881796705+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.881796705Z", "output_fields": {"evt.time.iso8601":1470327477881796705,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.881799840+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.881799840Z", "output_fields": {"evt.time.iso8601":1470327477881799840,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.882003104+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.882003104Z", "output_fields": {"evt.time.iso8601":1470327477882003104,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.882008208+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.882008208Z", "output_fields": {"evt.time.iso8601":1470327477882008208,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.882045694+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.882045694Z", "output_fields": {"evt.time.iso8601":1470327477882045694,"proc.cmdline":"cat /dev/null"}}
{"hostname":"test-falco-hostname","output":"2016-08-04T16:17:57.882054739+0000: Warning An open was seen (command=cat /dev/null)","priority":"Warning","rule":"open_from_cat","source":"syscall","tags":["filesystem","process","testing"],"time":"2016-08-04T16:17:57.882054739Z", "output_fields": {"evt.time.iso8601":1470327477882054739,"proc.cmdline":"cat /dev/null"}}
`)
