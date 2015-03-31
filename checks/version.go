package checks

import (
	"crypto/tls"
	"net"

	"github.com/dutchcoders/sslscanner/logger"
)

func CheckDeprecatedVersionSupported(version uint16) CheckFunc {
	return func(conn net.Conn) (net.Conn, error) {
		config := tls.Config{MinVersion: version, MaxVersion: version, InsecureSkipVerify: true}

		if tlsconn, err := TLSConnect(conn, config); err == nil {
			logger.Printf("Deprecated version %s supported: ok\n", Version(version).String())
			return tlsconn, nil
		} else {
			logger.Printf("Version %s:  %s\n", Version(version).String(), err.Error())
			return nil, err
		}
	}
}

func CheckVersionSupported(version uint16) CheckFunc {
	return func(conn net.Conn) (net.Conn, error) {
		config := tls.Config{MinVersion: version, MaxVersion: version, InsecureSkipVerify: true}

		if tlsconn, err := TLSConnect(conn, config); err == nil {
			logger.Printf("Version %s supported: ok\n", Version(version).String())
			return tlsconn, nil
		} else {
			logger.Printf("Version %s:  %s\n", Version(version).String(), err.Error())
			return nil, err
		}
	}
}

type Version uint16

func (s Version) String() string {
	switch uint16(s) {
	case tls.VersionSSL30:
		return "VersionSSL30"
	case tls.VersionTLS10:
		return "VersionTLS10"
	case tls.VersionTLS11:
		return "VersionTLS11"
	case tls.VersionTLS12:
		return "VersionTLS12"
	}
	return "Unknown"
}
