package scanners

import "net"

func POP3Scanner(conn net.Conn, fn InnerFunc) error {
	if _, err := fn(); err != nil {
		return err
	}

	return nil
}
