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

package run

import (
	"bytes"
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	testDockerImage = "ubuntu:latest"
)

func TestFileAccess(t *testing.T) {
	runners := map[string]func() (Runner, error){
		"executable": func() (Runner, error) { return NewExecutableRunner("/bin/cat") },
		"docker":     func() (Runner, error) { return NewDockerRunner(testDockerImage, "/bin/cat", nil) },
	}
	for rName, rCons := range runners {
		t.Run(rName, func(t *testing.T) {
			str := "hello world"
			file := NewStringFileAccessor("testdir/some-file", str)
			runner, err := rCons()
			require.Nil(t, err)
			var out bytes.Buffer
			err = runner.Run(
				context.Background(),
				WithStdout(&out),
				WithFiles(file),
				WithArgs(runner.WorkDir()+"/"+file.Name()),
			)
			require.Nil(t, err)
			require.Equal(t, str, out.String())
		})
	}
}

func TestInputOutput(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	runners := map[string]func() (Runner, error){
		"executable": func() (Runner, error) { return NewExecutableRunner("/bin/echo") },
		"docker":     func() (Runner, error) { return NewDockerRunner(testDockerImage, "/bin/echo", nil) },
	}
	for rName, rCons := range runners {
		t.Run(rName, func(t *testing.T) {
			runner, err := rCons()
			require.Nil(t, err)
			str := "hello world"
			var out bytes.Buffer
			err = runner.Run(
				context.Background(),
				WithStdout(&out),
				WithArgs(str),
			)
			require.Nil(t, err)
			require.Equal(t, str+"\n", out.String())
		})
	}
}
