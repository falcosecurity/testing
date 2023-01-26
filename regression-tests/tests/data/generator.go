package data

import (
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"
)

type largeFileInfo struct {
	VarName  string
	FileName string
	FilePath string
}

type textFileInfo struct {
	VarName     string
	FileName    string
	FileContent string
}

var textFileTemplate = template.Must(template.New("ruleFile").Parse(`
var {{ .VarName }} = utils.NewStringFileAccessor("{{ .FileName }}", ` + "`" + `{{ .FileContent }}` + "`)\n"))

var largeFileTemplate = template.Must(template.New("largeFile").Parse(`
var {{ .VarName }} = utils.NewLocalFileAccessor("{{ .FileName }}", "{{ .FilePath }}")
`))

type codeWriter func(io.Writer, string, string) error

func writeTextFileCode(w io.Writer, varName, fileName string) error {
	logrus.Infof("generating string file var %s from file %s", varName, fileName)
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	return textFileTemplate.Execute(w, textFileInfo{
		VarName:     varName,
		FileName:    path.Base(fileName),
		FileContent: string(data),
	})
}

func writeLargeFileCode(w io.Writer, varName, fileName string) error {
	logrus.Infof("generating local file var %s from file %s", varName, fileName)
	absPath, err := filepath.Abs(fileName)
	if err != nil {
		return err
	}
	return largeFileTemplate.Execute(w, largeFileInfo{
		VarName:  varName,
		FileName: path.Base(fileName),
		FilePath: absPath,
	})
}

func genCodeFromDir(w io.Writer, dirPath, namePath string, recursive bool, cw codeWriter, nameFilter func(string) bool) error {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		fileName := dirPath + file.Name()
		varName := strings.ReplaceAll(namePath+file.Name(), "/", "_")
		if file.IsDir() {
			if recursive {
				err = genCodeFromDir(w, fileName+"/", varName+"_", recursive, cw, nameFilter)
				if err != nil {
					return err
				}
			}
			continue
		}

		if !nameFilter(file.Name()) {
			continue
		}

		varName = strcase.ToCamel(strings.TrimSuffix(varName, path.Ext(file.Name())))
		err = cw(w, varName, fileName)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenCodeFromTextFilesDir(w io.Writer, dir string, recursive bool, nameFilter func(string) bool) error {
	return genCodeFromDir(w, dir, "", recursive, writeTextFileCode, nameFilter)
}

func GenCodeFromLargeFilesDir(w io.Writer, dir string, recursive bool, nameFilter func(string) bool) error {
	return genCodeFromDir(w, dir, "", recursive, writeLargeFileCode, nameFilter)
}
