package scanners

import (
	"net"
	"net/http"
	"net/url"
)

func HTTPSScanner(conn net.Conn, fn InnerFunc) error {
	var err error
	if conn, err = fn(); err != nil {
		return err
	}

	return HTTPScanner(conn, fn)
}

func HTTPScanner(conn net.Conn, fn InnerFunc) error {
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

	if _, err := client.Do(req); err == nil {
	} else {
		return err
	}

	return nil
}
