// SPDX-License-Identifier: Apache-2.0
//go:build ignore
// +build ignore

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
	tracesVersion := "20200831"
	traces := []string{"traces-info", "traces-positive", "traces-negative"}
	extractDir := data.DownloadDir + "/captures/"
	for _, traceName := range traces {
		url := fmt.Sprintf("https://download.falco.org/fixtures/trace-files/%s-%s.zip", traceName, tracesVersion)
		err := data.Download(url, data.DownloadDir+"/"+traceName+".zip")
		if err != nil {
			return nil, err
		}
		err = data.Unzip(data.DownloadDir+"/"+traceName+".zip", extractDir)
		if err != nil {
			return nil, err
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
