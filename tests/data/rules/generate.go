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

func main() {
	var fileInfos []*data.StringFileVarInfo
	files, err := data.DownloadAndListFalcoCodeFiles()
	die(err)

	baseDir := fmt.Sprintf("/falco-%s/test/rules", data.FalcoCodeVersion)
	for _, s := range files {
		if path.Ext(s) == ".yaml" && strings.Contains(s, baseDir) {
			content, err := os.ReadFile(s)
			die(err)
			prefix := s[:strings.LastIndex(s, baseDir)] + baseDir + "/"
			fileInfos = append(fileInfos, &data.StringFileVarInfo{
				VarName:     data.VarNameFromFilePath(s, prefix),
				FileName:    path.Base(s),
				FileContent: string(content),
			})
		}
	}

	out, err := os.Create("rules_gen.go")
	die(err)
	defer out.Close()
	err = data.GenSourceFile(out, &data.GenTemplateInfo{
		PackageName: "rules",
		Timestamp:   time.Now(),
		StringFiles: fileInfos,
	})
	die(err)
}
