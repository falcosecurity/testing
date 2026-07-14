// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

package testfalco

import (
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/pkg/run"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/captures"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// invalidUTF8Rule matches a filename that carries a raw invalid UTF-8 byte. The `\xff` escape authors the raw byte
// directly in the needle.
var invalidUTF8Rule = run.NewStringFileAccessor(
	"invalid_utf8_rule.yaml",
	`
- rule: open_invalid_utf8
  desc: open of a file whose name carries a raw invalid UTF-8 byte
  condition: evt.type in (open,openat,openat2) and fd.name contains "\xff"
  output: "file=%fd.name"
  priority: INFO
`,
)

// controlCharRule matches the opened path and outputs it; used to check that a control character in a field value is
// escaped, not emitted raw.
var controlCharRule = run.NewStringFileAccessor(
	"control_char_rule.yaml",
	`
- rule: open_control_char
  desc: open of a file whose name contains a control character
  condition: evt.type in (open,openat,openat2) and fd.name contains "/usr/lib/locale/locale-"
  output: "file=%fd.name"
  priority: INFO
`,
)

// validUTF8Rule carries valid multibyte UTF-8 in its output; used to check that valid UTF-8 passes through the output
// encoding unescaped.
var validUTF8Rule = run.NewStringFileAccessor(
	"valid_utf8_rule.yaml",
	`
- rule: open_valid_utf8
  desc: valid UTF-8 in the output must pass through unescaped
  condition: evt.type in (open,openat,openat2) and fd.name contains "locale-archive"
  output: "café=%fd.name"
  priority: INFO
`,
)

// nulStringRule uses a `\x00` needle on a string field; a NUL byte cannot be matched in a NUL-terminated string, so the
// rule must be rejected at load.
var nulStringRule = run.NewStringFileAccessor(
	"nul_string_rule.yaml",
	`
- rule: nul_string
  desc: a NUL byte needle on a string field is rejected
  condition: evt.type=execve and proc.name = "\x00"
  output: hit
  priority: INFO
`,
)

// nulByteBufRule uses a `\x00` needle on a byte buffer field, which is length-aware, so the rule loads and can match a
// NUL byte.
var nulByteBufRule = run.NewStringFileAccessor(
	"nul_bytebuf_rule.yaml",
	`
- rule: nul_bytebuf
  desc: a NUL byte needle on a byte buffer field is allowed
  condition: evt.type in (read,write) and evt.buffer = "\x00"
  output: hit
  priority: INFO
`,
)

// byteBufNulMatchRule matches a read/write whose byte buffer carries a raw NUL byte, using a `\x00` needle. Byte
// buffers are length-aware, so the raw NUL reaches matching at runtime.
var byteBufNulMatchRule = run.NewStringFileAccessor(
	"bytebuf_nul_match_rule.yaml",
	`
- rule: bytebuf_nul_match
  desc: a byte buffer carrying a raw NUL byte is matched by a NUL needle
  condition: evt.type in (read,write) and evt.buffer contains "\x00"
  output: "buf=%evt.buffer"
  priority: INFO
`,
)

// byteBufInvalidUTF8MatchRule matches a read/write whose byte buffer carries a raw invalid UTF-8 byte (0x90, a lone
// continuation byte), using a `\x90` needle.
var byteBufInvalidUTF8MatchRule = run.NewStringFileAccessor(
	"bytebuf_invalid_utf8_match_rule.yaml",
	`
- rule: bytebuf_invalid_utf8_match
  desc: a byte buffer carrying a raw invalid UTF-8 byte is matched by a raw-byte needle
  condition: evt.type in (read,write) and evt.buffer contains "\x90"
  output: "buf=%evt.buffer"
  priority: INFO
`,
)

// regexInvalidUTF8Rule matches the path via `regex`, whose subject is UTF-8-sanitized: the raw invalid byte reaches
// the regex engine as U+FFFD (matched here by `.`); before sanitization the regex engine would never match an
// invalid-UTF-8 subject.
var regexInvalidUTF8Rule = run.NewStringFileAccessor(
	"regex_invalid_utf8_rule.yaml",
	`
- rule: open_regex_invalid_utf8
  desc: regex matches the U+FFFD that an invalid UTF-8 byte is sanitized to
  condition: evt.type in (open,openat,openat2) and fd.name regex ".*locale-archiv."
  output: "file=%fd.name"
  priority: INFO
`,
)

// globInvalidUTF8Rule matches the path via `glob`, whose `?` matches a single raw byte by position, including the
// invalid UTF-8 byte, with no `\xHH` literal needed.
var globInvalidUTF8Rule = run.NewStringFileAccessor(
	"glob_invalid_utf8_rule.yaml",
	`
- rule: open_glob_invalid_utf8
  desc: glob '?' matches the invalid UTF-8 byte by position
  condition: evt.type in (open,openat,openat2) and fd.name glob "*locale-archiv?"
  output: "file=%fd.name"
  priority: INFO
`,
)

// regexRawInvalidByteRule puts a raw invalid byte in a `regex` pattern; the regex engine requires a valid UTF-8
// pattern, so the rule is rejected at load (raw invalid bytes belong to byte-aware operators).
var regexRawInvalidByteRule = run.NewStringFileAccessor(
	"regex_raw_invalid_byte_rule.yaml",
	`
- rule: regex_raw_invalid_byte
  desc: a raw invalid UTF-8 byte in a regex pattern is rejected
  condition: evt.type in (open,openat,openat2) and fd.name regex "\xff"
  output: hit
  priority: INFO
`,
)

// TestFalco_Output_InvalidUTF8Json checks that a raw invalid UTF-8 byte surfaced by a filtercheck reaches rule
// matching, while the JSON output Falco emits carries the U+FFFD replacement character, never the raw byte.
func TestFalco_Output_InvalidUTF8Json(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(invalidUTF8Rule),
		falco.WithCaptureFile(captures.InvalidUtf8),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	dets := res.Detections().OfRule("open_invalid_utf8")
	require.NotZero(t, dets.Count())
	fdName, ok := dets[0].OutputFields["fd.name"].(string)
	require.True(t, ok)
	assert.Contains(t, fdName, "\ufffd")
	assert.NotContains(t, fdName, "\xff")
}

// TestFalco_Output_InvalidUTF8PlainText checks that a raw invalid UTF-8 byte is emitted as U+FFFD in plain-text output,
// never as the raw byte.
func TestFalco_Output_InvalidUTF8PlainText(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(invalidUTF8Rule),
		falco.WithCaptureFile(captures.InvalidUtf8),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.Contains(t, res.Stdout(), "\ufffd")
	assert.NotContains(t, res.Stdout(), "\xff")
}

// TestFalco_Output_ControlCharPlainText checks that a control character (a newline) in a field value is escaped in
// plain-text output rather than emitted raw, which would forge log lines.
func TestFalco_Output_ControlCharPlainText(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(controlCharRule),
		falco.WithCaptureFile(captures.ControlChar),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.Contains(t, res.Stdout(), `locale-\nrchive`)    // escaped
	assert.NotContains(t, res.Stdout(), "locale-\nrchive") // never a raw newline
}

// TestFalco_Output_ValidUTF8PlainText checks that valid multibyte UTF-8 passes through plain-text output unescaped (not
// as \uXXXX escapes).
func TestFalco_Output_ValidUTF8PlainText(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithRules(validUTF8Rule),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.Contains(t, res.Stdout(), "café")
	assert.NotContains(t, res.Stdout(), `\u00e9`)
}

// TestFalco_Output_ControlCharJson checks that a control character (a newline) in a field value is escaped so the JSON
// stays valid and the value round-trips.
func TestFalco_Output_ControlCharJson(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(controlCharRule),
		falco.WithCaptureFile(captures.ControlChar),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	// Detections parsing proves the JSON stayed valid despite the control char.
	dets := res.Detections().OfRule("open_control_char")
	require.NotZero(t, dets.Count())
	fdName, ok := dets[0].OutputFields["fd.name"].(string)
	require.True(t, ok)
	assert.Contains(t, fdName, "\n")
}

// TestFalco_Output_ValidUTF8Json checks that valid multibyte UTF-8 is emitted raw in JSON output (not as `\uXXXX`
// escapes).
func TestFalco_Output_ValidUTF8Json(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(validUTF8Rule),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	assert.NotZero(t, res.Detections().Count())
	assert.Contains(t, res.Stdout(), "café")
	assert.NotContains(t, res.Stdout(), `\u00e9`)
}

// TestFalco_Output_BytebufNulMatch checks that a raw NUL byte carried by a byte buffer field reaches rule matching (a
// `\x00` needle) and that emitting the matched buffer keeps the JSON output valid.
func TestFalco_Output_BytebufNulMatch(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(byteBufNulMatchRule),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.NotZero(t, res.Detections().OfRule("bytebuf_nul_match").Count())
}

// TestFalco_Output_BytebufInvalidUTF8Match checks that a raw invalid UTF-8 byte carried by a byte buffer field reaches
// rule matching (a `\x90` needle) and that emitting the matched buffer keeps the JSON output valid.
func TestFalco_Output_BytebufInvalidUTF8Match(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(byteBufInvalidUTF8MatchRule),
		falco.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.NotZero(t, res.Detections().OfRule("bytebuf_invalid_utf8_match").Count())
}

// TestFalco_Output_RegexInvalidUTF8 checks that the `regex` subject is UTF-8-sanitized: a field holding a raw invalid
// byte is matched via the U+FFFD it becomes (a raw invalid subject would otherwise make the regex engine never match).
func TestFalco_Output_RegexInvalidUTF8(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(regexInvalidUTF8Rule),
		falco.WithCaptureFile(captures.InvalidUtf8),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.NotZero(t, res.Detections().OfRule("open_regex_invalid_utf8").Count())
}

// TestFalco_Output_GlobInvalidUTF8 checks that `glob`'s `?` matches a single raw byte by position, including a raw
// invalid UTF-8 byte, without a `\xHH` literal.
func TestFalco_Output_GlobInvalidUTF8(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRules(globInvalidUTF8Rule),
		falco.WithCaptureFile(captures.InvalidUtf8),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())
	assert.NotZero(t, res.Detections().OfRule("open_glob_invalid_utf8").Count())
}

// TestFalco_Validate_InvalidUTF8Json checks that `--validate -j` emits valid JSON and reports no errors for a
// well-formed rule whose condition carries a raw invalid UTF-8 byte.
func TestFalco_Validate_InvalidUTF8Json(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(invalidUTF8Rule),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	val := res.RuleValidation()
	require.NotNil(t, val)
	assert.Zero(t, val.AllErrors().Count())
}

// TestFalco_Validate_NulByteInStringRejected checks that a `\x00` needle on a string field fails to load: a NUL byte
// cannot be matched in a NUL-terminated string.
func TestFalco_Validate_NulByteInStringRejected(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(nulStringRule),
	)
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.NotZero(t, res.ExitCode(), res.ExitDesc())

	val := res.RuleValidation()
	require.NotNil(t, val)
	assert.NotZero(t, val.AllErrors().Count())
}

// TestFalco_Validate_NulByteInBytebufAccepted checks that a `\x00` needle on a byte buffer field loads: byte buffers
// are length-aware, so a NUL byte is a valid needle.
func TestFalco_Validate_NulByteInBytebufAccepted(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(nulByteBufRule),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	val := res.RuleValidation()
	require.NotNil(t, val)
	assert.Zero(t, val.AllErrors().Count())
}

// TestFalco_Validate_RegexRawInvalidByteRejected checks that a raw invalid UTF-8 byte in a `regex` pattern fails to
// load: the regex engine requires a valid UTF-8 pattern, so invalid bytes must be matched with a byte-aware operator
// instead.
func TestFalco_Validate_RegexRawInvalidByteRejected(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithOutputJSON(),
		falco.WithRulesValidation(regexRawInvalidByteRule),
	)
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.NotZero(t, res.ExitCode(), res.ExitDesc())

	val := res.RuleValidation()
	require.NotNil(t, val)
	assert.NotZero(t, val.AllErrors().Count())
}

// TestFalco_Describe_InvalidUTF8Json checks that `-L -j` emits valid JSON for a rule whose condition carries a raw
// invalid UTF-8 byte: the describe output is sanitized to U+FFFD.
func TestFalco_Describe_InvalidUTF8Json(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("-L"),
		falco.WithOutputJSON(),
		falco.WithRules(invalidUTF8Rule),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	desc := res.RulesetDescription()
	require.NotNil(t, desc)
	var found *falco.RuleDescription
	for i := range desc.Rules {
		if desc.Rules[i].Info.Name == "open_invalid_utf8" {
			found = &desc.Rules[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Contains(t, found.Details.ConditionCompiled, "\ufffd")
	assert.NotContains(t, found.Details.ConditionCompiled, "\xff")
}

// TestFalco_Describe_NulByteInBytebuf checks that -L -j describes a byte buffer rule whose needle carries a NUL byte;
// the describe output stays valid JSON with the NUL byte preserved.
func TestFalco_Describe_NulByteInBytebuf(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("-L"),
		falco.WithOutputJSON(),
		falco.WithRules(nulByteBufRule),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Zero(t, res.ExitCode(), res.ExitDesc())

	desc := res.RulesetDescription()
	require.NotNil(t, desc)
	var found *falco.RuleDescription
	for i := range desc.Rules {
		if desc.Rules[i].Info.Name == "nul_bytebuf" {
			found = &desc.Rules[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Contains(t, found.Details.ConditionCompiled, "\x00")
}
