package scanners

import "net"

type ScanFunc func(net.Conn, InnerFunc) error

type InnerFunc func() (net.Conn, error)

func Scan(fn ScanFunc) func(net.Conn, InnerFunc) error {
	return func(conn net.Conn, fn InnerFunc) error {
		conn, err := fn()
		return err
	}
}
