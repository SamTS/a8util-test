package util

import "github.com/sirupsen/logrus"

// Log is the logger for the app
var Log = logrus.New()

// SetLogLevel sets the global log level
func SetLogLevel(level logrus.Level) {
	Log.SetLevel(level)
}
