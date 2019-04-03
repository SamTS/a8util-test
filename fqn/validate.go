package fqn

import (
	"errors"
	"fmt"
	"strings"
)

// Validate takes in a fully qualified name in the format app.fn and
// returns the app name and the fn name separately. It returns an
// error of the passed fqn is not correctly formatted
func Validate(fullyQualifiedName string) error {
	appName, fnName, err := Parse(fullyQualifiedName)
	if err != nil {
		return err
	}

	var errorMessages []string

	// fn can't have a function or app name more than 30 characters
	if len(fnName) > 30 || len(fnName) < 3 {
		errorMessage := fmt.Sprintf("Function must be between 3 and 30 characters inclusive, current length is %d", len(fnName))
		errorMessages = append(errorMessages, errorMessage)
	}

	if len(appName) > 30 || len(appName) < 3 {
		errorMessage := fmt.Sprintf("App name must be between 3 and 30 characters inclusive, current length is %d", len(appName))
		errorMessages = append(errorMessages, errorMessage)
	}

	if len(errorMessages) > 0 {
		return errors.New(strings.Join(errorMessages, ", "))
	}

	return nil
}
