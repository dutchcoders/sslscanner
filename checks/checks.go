package checks

import "net"

type CheckFunc func(conn net.Conn) (net.Conn, error)
