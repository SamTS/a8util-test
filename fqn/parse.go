package fqn

import (
	"fmt"
	"strings"
)

// Parse takes in a fully qualified name in the format app.fn and
// returns the app name and the fn name separately. It returns an
// error of the passed fqn is not correctly formatted
// todo: why doesn't parse call validate?
func Parse(fullyQualifiedName string) (string, string, error) {
	fqnArray := strings.Split(fullyQualifiedName, ".")

	if len(fqnArray) != 2 {
		return "", "", fmt.Errorf("Please change the formnat of '%s' to 'namespace.function' where namespace and function contiain no periods", fullyQualifiedName)
	}

	appName := fqnArray[0]
	fnName := fqnArray[1]

	return appName, fnName, nil
}
