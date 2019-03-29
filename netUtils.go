package util

import (
	"net"

	"github.com/sirupsen/logrus"
)

// GetDomainIP gets the IP addresses associated with a domain name
func GetDomainIP(domainName string) []net.IP {
	ips, err := net.LookupIP(domainName)
	if err != nil {
		Log.WithFields(logrus.Fields{
			"domainName": domainName,
			"error":      err,
		}).Fatal("Failed to find IP Address for ")
	}

	var ipAddresses []net.IP

	for _, ip := range ips {
		ipAddresses = append(ipAddresses, ip)
		Log.WithFields(logrus.Fields{
			"ip": ip,
		}).Info("fnserver IP")
	}

	return ipAddresses
}
