package checks

import (
	"crypto/tls"
	"net"

	"github.com/dutchcoders/sslscanner/logger"
)

func CheckClient(certificate tls.Certificate) CheckFunc {
	return func(conn net.Conn) (net.Conn, error) {
		config := tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{certificate}}

		if tlsconn, err := TLSConnect(conn, config); err == nil {
			logger.Printf("Client certificate supported\n")
			return tlsconn, nil
		} else {
			logger.Printf("Client certificate not supported %s\n", err.Error())
			return nil, err
		}
	}
}
