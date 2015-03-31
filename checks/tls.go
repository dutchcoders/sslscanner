package checks

import (
	"crypto/tls"
	"net"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TLSConnect(conn net.Conn, config tls.Config) (*tls.Conn, error) {
	tlsconn := tls.Client(conn, &config)

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
		// fmt.Printf("err %#v %#v %#v\n", err, reflect.TypeOf(err), err.Error())
		return nil, err
	}

	return tlsconn, nil
}
