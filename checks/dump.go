package checks

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/dutchcoders/sslscanner/logger"
)

type SignatureAlgorithm x509.SignatureAlgorithm

func (a SignatureAlgorithm) String() string {
	switch x509.SignatureAlgorithm(a) {
	case x509.UnknownSignatureAlgorithm:
		return "UnknownSignatureAlgorithm"
	case x509.MD2WithRSA:
		return "MD2WithRSA"
	case x509.MD5WithRSA:
		return "MD5WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.DSAWithSHA1:
		return "DSAWithSHA1"
	case x509.DSAWithSHA256:
		return "DSAWithSHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSAWithSHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSAWithSHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSAWithSHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSAWithSHA512"
	}
	return ""
}

type PublicKeyAlgorithm x509.PublicKeyAlgorithm

func (a PublicKeyAlgorithm) String() string {
	switch x509.PublicKeyAlgorithm(a) {
	case x509.UnknownPublicKeyAlgorithm:
		return "UnknownPublicKeyAlgorithm"
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	}
	return "Unknown"
}

type KeyUsage x509.KeyUsage

func (a KeyUsage) String() string {
	s := []string{}
	if x509.KeyUsage(a)&x509.KeyUsageDigitalSignature != 0 {
		s = append(s, "KeyUsageDigitalSignature")
	}
	if x509.KeyUsage(a)&x509.KeyUsageContentCommitment != 0 {
		s = append(s, "KeyUsageContentCommitment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageKeyEncipherment != 0 {
		s = append(s, "KeyUsageKeyEncipherment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageDataEncipherment != 0 {
		s = append(s, "KeyUsageDataEncipherment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageKeyAgreement != 0 {
		s = append(s, "KeyUsageKeyAgreement")
	}
	if x509.KeyUsage(a)&x509.KeyUsageCertSign != 0 {
		s = append(s, "KeyUsageCertSign")
	}
	if x509.KeyUsage(a)&x509.KeyUsageCRLSign != 0 {
		s = append(s, "KeyUsageCRLSign")
	}
	if x509.KeyUsage(a)&x509.KeyUsageEncipherOnly != 0 {
		s = append(s, "KeyUsageEncipherOnly")
	}
	if x509.KeyUsage(a)&x509.KeyUsageDecipherOnly != 0 {
		s = append(s, "KeyUsageDecipherOnly")
	}

	return strings.Join(s, ",")
}

type ExtKeyUsage x509.ExtKeyUsage

func (a ExtKeyUsage) String() string {
	if x509.ExtKeyUsage(a)&x509.ExtKeyUsageAny != 0 {
	}
	/*        ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
	*/
	return ""
}

func DumpCertificates() CheckFunc {
	return func(conn net.Conn) error {
		config := tls.Config{InsecureSkipVerify: true}

		tlsconn, err := TLSConnect(conn, config)
		if err != nil {
			return err
		}

		connState := tlsconn.ConnectionState()

		for _, c := range connState.PeerCertificates {
			logger.Printf("Subject: %s (%s)\nIssuer: %s (%s)\nVersion: %d\nNotBefore: %s\nNotAfter:%s",
				strings.Join(c.Subject.Organization, ", "),
				c.Subject.CommonName,
				strings.Join(c.Issuer.Organization, ", "),
				c.Issuer.CommonName,
				c.Version,
				c.NotBefore,
				c.NotAfter)

			if len(c.PermittedDNSDomains) > 0 {
				logger.Printf("PermittedDNSNames: %s\n", strings.Join(c.PermittedDNSDomains, ", "))
			}

			if len(c.DNSNames) > 0 {
				logger.Printf("DNSNames: %s\n", strings.Join(c.DNSNames, ", "))
			}

			logger.Printf("Keyusage %s (%d)\n", KeyUsage(c.KeyUsage).String(), c.KeyUsage)
			// logger.Printf("ExtKeyusage %s\n", ExtKeyUsage(c.ExtKeyUsage).String())
			logger.Printf("ExtKeyusage %d\n", c.ExtKeyUsage)
			logger.Printf("Publickey Algorithm: %s\n", PublicKeyAlgorithm(c.PublicKeyAlgorithm).String())
			logger.Printf("Signature Algorithm: %s\n", SignatureAlgorithm(c.SignatureAlgorithm).String())
		}

		for r := range connState.VerifiedChains {
			vchains := &connState.VerifiedChains[r]
			fmt.Printf("Verified Chains %d : %d\n", r, vchains)
			_ = r

		}
		return nil
	}
}
