package util

import (
	"errors"
	"net"

	"github.com/sirupsen/logrus"
)

// todo: move this function into a library
func HostnameToIp(hostname string) (string, error) {
	//net.LookupIP produces an array of ipv4 or ipv6 addresses, we will need ot filter them
	ipAddrArray, err := net.LookupIP(hostname)
	if err != nil {
		Log.WithFields(logrus.Fields{
			"hostname": hostname,
		}).Error("hostname not found")

		return "", errors.New("hostname not found")
	}

	//Now go through the array of ipAddrs and grab the first ipv4 address
	ipAddr := net.ParseIP("127.0.0.1")
	for _, addr := range ipAddrArray {
		if addr.To4() != nil {
			ipAddr = addr
			break
		}
	}

	return ipAddr.String(), nil
}
