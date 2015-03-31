package logger

import (
	"io/ioutil"
	"log"
)

var logger = NewNullLogger()

func NewNullLogger() *log.Logger {
	return log.New(ioutil.Discard, "", log.Ldate|log.Ltime)
}

func SetLogger(l *log.Logger) {
	logger = l
}

func Printf(format string, v ...interface{}) {
	logger.Printf(format, v...)
}
