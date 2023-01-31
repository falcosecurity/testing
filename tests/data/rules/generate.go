//go:build ignore
// +build ignore

package main

import (
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jasondellaluce/falco-testing/tests/data"
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

	baseDir := "/falco-0.33.1/test/rules"
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
