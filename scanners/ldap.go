package scanners

import "net"

func LDAPScanner(conn net.Conn, fn InnerFunc) error {
	if _, err := fn(); err != nil {
		return err
	}

	return nil
}
