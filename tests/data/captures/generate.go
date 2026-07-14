// SPDX-License-Identifier: Apache-2.0
//go:build ignore
// +build ignore

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

package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/falcosecurity/testing/tests/data"
)

func die(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func downloadFalcoOrgTraces() ([]*data.LargeFileVarInfo, error) {
	var res []*data.LargeFileVarInfo
	traces := []struct{ localName, remoteName string }{
		{"traces-info", "traces-info-20200831"},
		{"traces-positive", "traces-positive-20200831"},
		{"traces-negative", "traces-negative-20200831"},
		{"traces-utf8", "traces-utf8"},
	}
	extractDir := data.DownloadDir + "/captures/"
	for _, trace := range traces {
		url := fmt.Sprintf("https://download.falco.org/fixtures/trace-files/%s.zip", trace.remoteName)
		traceFilePath := data.DownloadDir + "/" + trace.localName + ".zip"
		if err := data.Download(url, traceFilePath); err != nil {
			return nil, fmt.Errorf("error downloading trace file %s (%s): %w", trace.localName, trace.remoteName, err)
		}

		if err := data.Unzip(traceFilePath, extractDir); err != nil {
			return nil, fmt.Errorf("error unzipping trace file %s in %s: %w", traceFilePath, extractDir, err)
		}
	}
	dirFiles, err := data.ListDirFiles(extractDir, true)
	if err != nil {
		return nil, err
	}
	for _, s := range dirFiles {
		if path.Ext(s) == ".scap" {
			res = append(res, &data.LargeFileVarInfo{
				VarName:  data.VarNameFromFilePath(s, extractDir),
				FileName: path.Base(s),
				FilePath: s,
			})
		}
	}
	return res, nil
}

func downloadFalcoCodeTraces() ([]*data.LargeFileVarInfo, error) {
	var res []*data.LargeFileVarInfo
	files, err := data.DownloadAndListFalcoCodeFiles()
	if err != nil {
		return nil, err
	}
	baseDir := fmt.Sprintf("/falco-%s/test/trace_files", data.FalcoCodeVersion)
	for _, s := range files {
		if (path.Ext(s) == ".scap" || path.Ext(s) == ".json") && strings.Contains(s, baseDir) {
			prefix := s[:strings.LastIndex(s, baseDir)] + baseDir + "/"
			res = append(res, &data.LargeFileVarInfo{
				VarName:  data.VarNameFromFilePath(s, prefix),
				FileName: path.Base(s),
				FilePath: s,
			})
		}
	}
	return res, nil
}

func main() {
	falcoOrgFiles, err := downloadFalcoOrgTraces()
	die(err)
	falcoCodeFiles, err := downloadFalcoCodeTraces()
	die(err)

	out, err := os.Create("captures_gen.go")
	die(err)
	defer out.Close()
	err = data.GenSourceFile(out, &data.GenTemplateInfo{
		PackageName: "captures",
		Timestamp:   time.Now(),
		LargeFiles:  append(falcoOrgFiles, falcoCodeFiles...),
	})
	die(err)
}
