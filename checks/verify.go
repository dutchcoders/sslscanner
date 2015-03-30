package checks

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type VerifyFunc func(*x509.Certificate) error

func VerifyValidAfter() VerifyFunc {
	return func(c *x509.Certificate) error {
		now := time.Now()

		if now.After(c.NotAfter) {
			return fmt.Errorf("Certificate expired %s.", c.NotAfter.Format("Jan 2 2006"))
		}
		return nil
	}
}

func VerifyAuthority() VerifyFunc {
	return func(c *x509.Certificate) error {
		return nil
	}
}

func VerifyHostname(hostname string) VerifyFunc {
	return func(c *x509.Certificate) error {
		if err := c.VerifyHostname(hostname); err != nil {
			return err
		}

		return nil
	}
}

func VerifyValidBefore() VerifyFunc {
	return func(c *x509.Certificate) error {
		now := time.Now()

		if now.Before(c.NotBefore) {
			return fmt.Errorf("Certificate not yet valid %s.", c.NotBefore.Format("Jan 2 2006"))
		}
		return nil
	}
}

// http://golang.org/src/crypto/x509/verify.go?s=7077:7162#L202
func Verify(verifyFns ...VerifyFunc) CheckFunc {
	return func(conn net.Conn) error {
		config := tls.Config{InsecureSkipVerify: true}

		var tlsconn *tls.Conn
		var err error
		if tlsconn, err = TLSConnect(conn, config); err != nil {
			return err
		}

		connState := tlsconn.ConnectionState()

		c := connState.PeerCertificates[0]

		for _, verifyFn := range verifyFns {
			if err = verifyFn(c); err != nil {
				fmt.Println(err.Error())
			}
		}

		return nil
	}
}
