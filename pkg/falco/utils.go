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

package falco

import (
	"bufio"
	"io"
	"time"
)

func skewedDuration(d time.Duration) time.Duration {
	return time.Duration(float64(d) * 1.10)
}

func readLineByLine(r io.Reader) ([]string, error) {
	var res []string
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		res = append(res, scanner.Text())
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return res, nil
}

func removeFromArgs(args []string, arg string, nparams int) []string {
	var res []string
	for i := 0; i < len(args); i++ {
		if args[i] == arg {
			i += nparams
		} else {
			res = append(res, args[i])
		}
	}
	return res
}
