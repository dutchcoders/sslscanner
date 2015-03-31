package scanners

import "net"

type ScanFunc func(net.Conn, InnerFunc) error

type InnerFunc func() (net.Conn, error)

func Scanner(fn2 ScanFunc) func(net.Conn, InnerFunc) error {
	return func(conn net.Conn, fn InnerFunc) error {
		err := fn2(conn, fn)
		return err
	}
}
