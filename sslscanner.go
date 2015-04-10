package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/davecgh/go-spew/spew"
	"gopkg.in/alecthomas/kingpin.v1"

	"github.com/dutchcoders/sslscanner/checks"
	"github.com/dutchcoders/sslscanner/logger"
	"github.com/dutchcoders/sslscanner/scanners"

	// plugins "sslscanner/plugins"
)

// http://miek.nl/posts/2014/Aug/16/go-dns-package/

// connect to port
// retrieve all certificates
// check the certificates
// show warning or error to certificate

// rename Scanner to Plugin?
// embed defaultscanner in plugin itself?

// scan multiple ports for ip
// different scanners
// have multiple ssl resolvers / port responders
// multiple ips
// detect warnings, eg ssl sha1 usage, rc4 usage, name usage
// threat warnings as errors

// multiple protocols
// flexible ssl checks
// flexibele plugins
// warnings en errors terug
// retrieve info about the certificates
// test the info about the certficates
// comparable with go test

// add generic tls client scanner

func Connect(ip net.IP, port int) (net.Conn, error) {
	dialer := new(net.Dialer)
	dialer.Timeout = time.Duration(60) * time.Second
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	return conn, err
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type IPAndHostname struct {
	IP       net.IP
	Hostname string
}

// will parse arguments and return channel with ips
func parseArgs(args []string) chan IPAndHostname {
	out := make(chan IPAndHostname)

	go func() {
		for _, arg := range args {
			// resolve cidr
			if ip, ipnet, err := net.ParseCIDR(arg); err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
					out <- IPAndHostname{IP: ip, Hostname: ""}
				}
				continue
			}
			// single ip
			ip := net.ParseIP(arg)
			if ip != nil {
				out <- IPAndHostname{IP: ip, Hostname: ""}
				continue
			}

			// resolve hostname
			if ips, err := net.LookupIP(arg); err == nil {
				for _, ip := range ips {
					out <- IPAndHostname{IP: ip, Hostname: arg}
				}
				continue
			}

			fmt.Printf("Cannot understand or resolve %s\n", arg)
		}

		close(out)
	}()

	// close channel
	return out
}

type PortStatus int

const (
	PortStatusOpen PortStatus = iota
)

var ErrNotImplemented = errors.New("Not implemented")

func SSHScan(conn net.Conn) error {
	return ErrNotImplemented
}

func LoadClientCertificate(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func LoadRootCertificates(r io.Reader) (*x509.CertPool, error) {
	fs := x509.NewCertPool()

	pemCerts, err := ioutil.ReadAll(r)
	if err != nil {
		return fs, err
	}

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fs, err
		}

		fs.AddCert(cert)

		logger.Printf("Loaded root certificate %s.", cert.Subject.CommonName)
	}

	return fs, nil
}

/*
type SSLScanner struct {
}

type SSLScannerConfig struct {
}

func NewSSLScanner(conf SSLScannerConfig) *SSLScanner {
	scanner := &SSLScanner{}
	return scanner
}*/

func main() {
	var (
		debug  = kingpin.Flag("debug", "enable debug mode").Short('d').Default("false").Bool()
		https  = kingpin.Flag("enable-https", "enable http scan").Default("false").Bool()
		smtp   = kingpin.Flag("enable-smtp", "enable smtp scan").Default("false").Bool()
		imap   = kingpin.Flag("enable-imap", "enable imap scan").Default("false").Bool()
		ftp    = kingpin.Flag("enable-ftp", "enable ftp scan").Default("false").Bool()
		pop3   = kingpin.Flag("enable-pop3", "enable pop3 scan").Default("false").Bool()
		ldap   = kingpin.Flag("enable-ldap", "enable ldap scan").Default("false").Bool()
		ranges = kingpin.Arg("ips", "range, ip address or hostname").Required().Strings()
		ports  = kingpin.Flag("ports", "ports to scan").Short('p').Required().String()
		format = kingpin.Flag("format", "output format to use").Short('f').Default("text").Enum("xml", "json", "text")
		root   = kingpin.Flag("root", "").File()
		client = kingpin.Flag("client", "").File()
	)

	kingpin.Parse()

	_ = format

	if *debug {
		logger.SetLogger(log.New(os.Stderr, "", log.Ldate|log.Ltime))
	}

	scannerFuncs := []scanners.ScanFunc{}

	if *https {
		scannerFuncs = append(scannerFuncs, scanners.Scanner(scanners.HTTPSScanner))
	}

	if *pop3 {
		scannerFuncs = append(scannerFuncs, scanners.Scanner(scanners.POP3Scanner))
	}
	if *smtp {
		scannerFuncs = append(scannerFuncs, scanners.Scanner(scanners.SMTPScanner))
	}
	if *imap {
		scannerFuncs = append(scannerFuncs, scanners.Scanner(scanners.IMAPScanner))
	}
	if *ldap {
		scannerFuncs = append(scannerFuncs, scanners.Scanner(scanners.IMAPScanner))
	}
	if *ftp {
		scannerFuncs = append(scannerFuncs, scanners.Scanner(scanners.FTPScanner))
	}

	if len(scannerFuncs) == 0 {
		fmt.Println("No scanners selected.")
		os.Exit(0)
	}

	for hostnameAndIp := range parseArgs(*ranges) {
		hostname := hostnameAndIp.Hostname
		ip := hostnameAndIp.IP

		report := NewReport(ip)

		// reverse lookup
		var err error
		if report.Hostnames, err = net.LookupAddr(ip.String()); err == nil {
			logger.Printf("Reverse hostnames %s.\n", strings.Join(report.Hostnames, ", "))
		} else if err != nil {
			logger.Printf("Error during reverse lookup: %s\n", err)
		}

		// check ports
		for _, port_str := range strings.Split(*ports, ",") {
			port_str = strings.Trim(port_str, " ")
			port, err := strconv.Atoi(port_str)
			if err != nil {
				fmt.Printf("Invalid port number %s\n.", port_str)
				continue
			}

			// specific checks for hostname and ip
			checkFuncs := []checks.CheckFunc{
				checks.CheckDeprecatedVersionSupported(tls.VersionSSL30),
				checks.CheckVersionSupported(tls.VersionTLS10),
				checks.CheckVersionSupported(tls.VersionTLS11),
				checks.CheckVersionSupported(tls.VersionTLS12),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				checks.CheckDeprecatedSuiteSupported(tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA),
				checks.CheckDeprecatedSuiteSupported(tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
				checks.CheckDeprecatedSuiteSupported(tls.TLS_RSA_WITH_RC4_128_SHA),
				checks.CheckSuiteSupported(tls.TLS_RSA_WITH_AES_128_CBC_SHA),
				checks.CheckSuiteSupported(tls.TLS_RSA_WITH_AES_256_CBC_SHA),
				checks.CheckSuiteSupported(tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
				checks.CheckSuiteSupported(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA),
				checks.DumpCertificates(),
				checks.Verify(
					checks.VerifyValidBefore(),
					checks.VerifyValidAfter(),
					checks.VerifyAuthority(),
					checks.VerifyHostname(hostname),
				),
				// CheckHeartBlead(),
				// CheckPoodle() <
				// CheckDomainName(),
				// CheckClientCertificate(),
				// CheckServerName(),
			}

			if *root != nil {
				logger.Printf("Loading root certificates %s.", (*root).Name())
				if certPool, err := LoadRootCertificates(*root); err == nil {
					checkFuncs = append(checkFuncs, checks.CheckRoot(certPool))
				} else if err != nil {
					logger.Printf("Error during loading root certificates: %s", err.Error())
					os.Exit(1)
				}
			}

			if *client != nil {
				logger.Printf("Loading client certificate %s.", (*client).Name())
				if certificates, err := LoadClientCertificate("test.pem", "test.cert"); err == nil {
					checkFuncs = append(checkFuncs, checks.CheckClient(certificates))
				} else if err != nil {
					logger.Printf("Error during loading client certificates: %s.", err.Error())
					os.Exit(1)
				}
			}

			logger.Printf("Scanning %s (%d) (%s): ", ip, port, hostname)

			for _, scannerFn := range scannerFuncs {
				for _, checkFn := range checkFuncs {
					var conn net.Conn
					var err error
					if conn, err = Connect(ip, port); err != nil {
						logger.Printf("Couldn't connect to %s: %s.\n", ip, err.Error())
						continue
					}

					defer conn.Close()

					// the inner function is not necessary anymore
					err = scannerFn(conn, func() (net.Conn, error) {
						return checkFn(conn)
					})

					if err != nil {
						logger.Printf("Protocol error %s: %s.\n", ip, err.Error())
						continue
					}
				}
			}
		}
	}

	// output reporter
}
