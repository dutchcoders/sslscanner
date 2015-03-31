package checks

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/dutchcoders/sslscanner/logger"
)

func CheckRoot(pool *x509.CertPool) CheckFunc {
	return func(conn net.Conn) error {
		config := tls.Config{InsecureSkipVerify: true, RootCAs: pool}

		if _, err := TLSConnect(conn, config); err != nil {
			logger.Printf("CA invalid %s\n", err.Error())
			return nil
		}
		logger.Printf("CA valid\n")
		return nil
	}
}
