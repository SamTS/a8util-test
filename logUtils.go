package util 

import "github.com/sirupsen/logrus"

// Log is the logger for the app
var Log = logrus.New()

// Fatal is a helper for setting the logrus FatalLeve
var Fatal = logrus.FatalLevel

// Error is a helper for setting the logrus ErrorLeve
var Error = logrus.ErrorLevel

// Warn is a helper for setting the logrus WarnLeve
var Warn = logrus.WarnLevel

// Info is a helper for setting the logrus InfoLevel
var Info = logrus.InfoLevel

// Debug is a helper for setting the logrus DebugLevel
var Debug = logrus.DebugLevel

// Trace is a helper for setting the logrus TraceLevel
var Trace = logrus.TraceLevel

type Fields = logrus.Fields

// SetLogLevel sets the global log level
func SetLogLevel(level logrus.Level) {
	Log.SetLevel(level)
}
