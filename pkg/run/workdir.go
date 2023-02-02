package run

import (
	"fmt"
	"os"
)

const (
	execRunnerWorkDirPrefix = "falco-testing-workdir-"
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
