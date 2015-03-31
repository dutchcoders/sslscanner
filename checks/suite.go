package checks

import (
	"crypto/tls"
	"net"

	"github.com/dutchcoders/sslscanner/logger"
)

func CheckDeprecatedSuiteSupported(suite uint16) CheckFunc {
	return func(conn net.Conn) (net.Conn, error) {
		config := tls.Config{CipherSuites: []uint16{suite}, InsecureSkipVerify: true}

		if tlsconn, err := TLSConnect(conn, config); err == nil {
			logger.Printf("Deprecated cipher suite %s supported.\n", CipherSuite(suite).String())
			return tlsconn, nil
		} else {
			logger.Printf("Cipher suite %s:  %s\n", CipherSuite(suite).String(), err.Error())
			return nil, err
		}

	}
}

func CheckSuiteSupported(suite uint16) CheckFunc {
	return func(conn net.Conn) (net.Conn, error) {
		config := tls.Config{CipherSuites: []uint16{suite}, InsecureSkipVerify: true}

		if tlsconn, err := TLSConnect(conn, config); err == nil {
			logger.Printf("Cipher suite %s supported: ok\n", CipherSuite(suite).String())
			return tlsconn, nil
		} else {
			logger.Printf("Cipher suite %s:  %s\n", CipherSuite(suite).String(), err.Error())
			return nil, err
		}
	}
}

type CipherSuite uint16

func (s CipherSuite) String() string {
	switch uint16(s) {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_FALLBACK_SCSV:
		return "TLS_FALLBACK_SCSV"
	}
	return "Unknown"
}
