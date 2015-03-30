package checks

import (
	"crypto/tls"
	"net"
)

func CheckClient(certificate tls.Certificate) CheckFunc {
	return func(conn net.Conn) error {
		config := tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{certificate}}

		if _, err := TLSConnect(conn, config); err != nil {
			logger.Printf("Client certificate not supported %s\n", err.Error())
			return nil
		}
		logger.Printf("Client certificate supported\n")
		return nil
	}
}
