package checks

import (
	"log"
	"net"
	"os"
)

var logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)

type CheckFunc func(conn net.Conn) error
