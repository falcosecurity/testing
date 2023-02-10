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
