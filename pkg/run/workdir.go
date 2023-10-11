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
	"fmt"
	"os"
)

const (
	execRunnerWorkDirPrefix = "falcosecurity-testing-workdir-"
)

// WorkDir creates a temporary work directory, runs an action, and removes
// the directory afterwards. Returns a non-nil error in case of issues.
func WorkDir(f func(string)) error {
	dir, err := os.MkdirTemp("", execRunnerWorkDirPrefix)
	if err != nil {
		return fmt.Errorf("can't create workdir: %s", err.Error())
	}
	f(dir)
	err = os.RemoveAll(dir)
	if err != nil {
		return fmt.Errorf("can't remove workdir '%s': %s", dir, err.Error())
	}
	return nil
}
