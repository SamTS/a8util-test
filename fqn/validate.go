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

	const min = 2
	const max = 30

	// fn can't have a function or app name more than 30 characters
	if len(fnName) > max || len(fnName) < min {
		errorMessage := fmt.Sprintf("Function must be between %d and %d characters inclusive, current length is %d", min, max, len(fnName))
		errorMessages = append(errorMessages, errorMessage)
	}

	if len(appName) > max || len(appName) < min {
		errorMessage := fmt.Sprintf("App name must be between %d and %d characters inclusive, current length is %d", min, max, len(appName))
		errorMessages = append(errorMessages, errorMessage)
	}

	if len(errorMessages) > 0 {
		return errors.New(strings.Join(errorMessages, ", "))
	}

	return nil
}
