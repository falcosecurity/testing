package tests

import (
	"github.com/jasondellaluce/falco-testing/pkg/falco"
	"github.com/sirupsen/logrus"
)

var FalcoExecutable = falco.DefaultFalcoExecutable
var LogLevel = logrus.DebugLevel

func init() {
	logrus.SetLevel(LogLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}
