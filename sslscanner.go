package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/alecthomas/kingpin.v1"
)

// scan multiple ports for ip
// different scanners
// have multiple ssl resolvers / port responders
// multiple ips
// detect warnings, eg ssl sha1 usage, rc4 usage, name usage
// threat warnings as errors

type Scanner interface {
	Scan(ip net.IP, port int) (net.Conn, error)
}

type DefaultScanner struct {
	Scanner
}

func (s *DefaultScanner) Scan(ip net.IP, port int) (net.Conn, error) {
	dialer := new(net.Dialer)
	dialer.Timeout = time.Duration(1) * time.Second
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	return conn, err
}

func NewDefaultScanner() Scanner {
	return &DefaultScanner{}
}

type TLSExtract struct {
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func (s *TLSExtract) Extract(conn net.Conn) error {
	tlsconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})

	errChannel := make(chan error, 2)

	timeout := time.Duration(1) * time.Second
	time.AfterFunc(timeout, func() {
		errChannel <- timeoutError{}
	})

	go func() {
		errChannel <- tlsconn.Handshake()
	}()

	err := <-errChannel

	if err != nil {
		return err
	}

	for _, c := range tlsconn.ConnectionState().PeerCertificates {
		fmt.Printf("Subject: %s (%s)\nIssuer: %s (%s)\nVersion: %d\nNotBefore: %s\nNotAfter:%s",
			strings.Join(c.Subject.Organization, ", "),
			c.Subject.CommonName,
			strings.Join(c.Issuer.Organization, ", "),
			c.Issuer.CommonName,
			c.Version,
			c.NotBefore,
			c.NotAfter)

		fmt.Println(strings.Join(c.PermittedDNSDomains, ", "))
		fmt.Println(strings.Join(c.DNSNames, ", "))
		fmt.Printf("Keyusage %d\n", c.KeyUsage)
		fmt.Printf("Publickey Algorithm %d\n", c.PublicKeyAlgorithm)
		switch c.PublicKeyAlgorithm {
		case x509.UnknownPublicKeyAlgorithm:
			fmt.Println("UnknownPublicKeyAlgorithm")
		case x509.RSA:
			fmt.Println("RSA")
		case x509.DSA:
			fmt.Println("DSA")
		case x509.ECDSA:
			fmt.Println("ECDSA")
		}
		fmt.Printf("Signature Algorithm %d\n", c.SignatureAlgorithm)
		switch c.SignatureAlgorithm {
		case x509.UnknownSignatureAlgorithm:
			fmt.Println("UnknownSignatureAlgorithm")
		case x509.MD2WithRSA:
			fmt.Println("MD2WithRSA")
		case x509.MD5WithRSA:
			fmt.Println("MD5WithRSA")
		case x509.SHA1WithRSA:
			fmt.Println("SHA1WithRSA")
		case x509.SHA256WithRSA:
			fmt.Println("SHA256WithRSA")
		case x509.SHA384WithRSA:
			fmt.Println("SHA384WithRSA")
		case x509.SHA512WithRSA:
			fmt.Println("SHA512WithRSA")
		case x509.DSAWithSHA1:
			fmt.Println("DSAWithSHA1")
		case x509.DSAWithSHA256:
			fmt.Println("DSAWithSHA256")
		case x509.ECDSAWithSHA1:
			fmt.Println("ECDSAWithSHA1")
		case x509.ECDSAWithSHA256:
			fmt.Println("ECDSAWithSHA256")
		case x509.ECDSAWithSHA384:
			fmt.Println("ECDSAWithSHA384")
		case x509.ECDSAWithSHA512:
			fmt.Println("ECDSAWithSHA512")
		}

	}
	return nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// will parse arguments and return channel with ips
func parseArgs(args []string) chan net.IP {
	out := make(chan net.IP)

	go func() {
		for _, arg := range args {
			// resolve cidr
			if ip, ipnet, err := net.ParseCIDR(arg); err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
					out <- ip
				}
			}

			// single ip
			ip := net.ParseIP(arg)
			if ip != nil {
				out <- ip
			}

			// resolve hostname
			if ips, err := net.LookupIP(arg); err == nil {
				for _, ip := range ips {
					out <- ip
				}
			}

		}

		close(out)
	}()

	// close channel
	return out
}

func NewNullLogger() *log.Logger {
	return log.New(ioutil.Discard, "", log.Ldate|log.Ltime)
}

var logger = NewNullLogger()

type PortStatus int

const (
	PortStatusOpen PortStatus = iota
)

type ScanFunc func(net.Conn) error

func Scan(fn ScanFunc) func(net.Conn) error {
	return func(conn net.Conn) error {
		return fn(conn)
	}
}

func HTTPBanner(conn net.Conn) error {
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (c net.Conn, err error) {
				return conn, nil
			},
		},
	}

	req := &http.Request{
		Method:     "HEAD",
		URL:        &url.URL{Scheme: "http", Host: "sc.ann.er", Path: "/"},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       nil,
		Host:       "",
	}

	if resp, err := client.Do(req); err == nil {
		logger.Printf("Server banner '%s';", resp.Header.Get("Server"))
	} else {
		return err
	}

	return nil
}

var ErrNotImplemented = errors.New("Not implemented")

func SSHScan(conn net.Conn) error {
	return ErrNotImplemented
}

func TLSScan(conn net.Conn) error {
	// will extract the tls
	extract := TLSExtract{}
	if err := extract.Extract(conn); err != nil {
		logger.Printf("%s\n", err)
		return err
	}

	return nil
}

func main() {
	var (
		debug  = kingpin.Flag("debug", "enable debug mode").Short('d').Default("false").Bool()
		ranges = kingpin.Arg("ips", "range, ip address or hostname").Required().Strings()
		ports  = kingpin.Flag("ports", "ports to scan").Short('p').Required().String()
		format = kingpin.Flag("format", "output format to use").Short('f').Default("text").Enum("xml", "json", "text")
	)

	kingpin.Parse()

	fmt.Println(*format)

	if *debug {
		logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)
	}

	scanners := []ScanFunc{
		Scan(TLSScan),
		Scan(HTTPBanner),
	}

	for ip := range parseArgs(*ranges) {
		// reverse lookup
		report := NewReport(ip)

		var err error
		if report.Hostnames, err = net.LookupAddr(ip.String()); err != nil {
			logger.Printf("Error during reverse lookup: %s\n", err)
		}

		// parallel
		for _, port := range strings.Split(*ports, ",") {
			port = strings.Trim(port, " ")
			port, _ := strconv.Atoi(port)

			logger.Printf("Scanning %s (%d): ", ip, port)

			for _, scanner := range scanners {
				var conn net.Conn
				var err error
				if conn, err = NewDefaultScanner().Scan(ip, port); err != nil {
					logger.Printf("%s\n", err)
					break
				}

				defer conn.Close()

				// port is open
				report.Ports[port] = PortStatusOpen

				// will extract the tls
				if err = scanner(conn); err != nil {
					logger.Printf("%s\n", err)
				}

				// extract.Check() for red flags
			}
		}
	}

	// output
}
