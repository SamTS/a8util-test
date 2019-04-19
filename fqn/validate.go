package fqn

import (
	"errors"
	"fmt"
	"log"
	"regexp"
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
	err = CheckLength(fnName)
	if err != nil {
		errorMessages = append(errorMessages, "Function "+err.Error())
	}

	err = CheckLength(appName)
	if err != nil {
		errorMessages = append(errorMessages, "Namespace "+err.Error())
	}

	// fn and docker can't have names that have upper case or interesting characters in them
	err = CheckCharacters(fnName)
	if err != nil {
		errorMessages = append(errorMessages, "Function "+err.Error())
	}

	err = CheckCharacters(appName)
	if err != nil {
		errorMessages = append(errorMessages, "Namespace "+err.Error())
	}

	if len(errorMessages) > 0 {
		return errors.New(strings.Join(errorMessages, "\n"))
	}

	return nil
}

func CheckLength(msg string) error {
	const min = 2
	const max = 30

	if len(msg) > max || len(msg) < min {
		return errors.New(fmt.Sprintf("name must be between %d and %d characters inclusive, current length is %d", min, max, len(msg)))
	}

	return nil
}

func CheckCharacters(msg string) error {

	lowerString := strings.ToLower(msg)

	reg, err := regexp.Compile("[^a-z0-9_]+")
	if err != nil {
		log.Fatal(err)
	}

	processedString := reg.ReplaceAllString(lowerString, "")

	validated := processedString == msg

	if !validated {
		return errors.New("characters may only be lowercase, digits and '_'")
	}

	return nil
}
