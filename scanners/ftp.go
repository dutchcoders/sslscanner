package scanners

import (
	"net"
	"net/textproto"
)

type FTPClient struct {
	Text *textproto.Conn
}

func NewFTPClient(conn net.Conn) (*FTPClient, error) {
	tconn := textproto.NewConn(conn)
	_, _, err := tconn.ReadCodeLine(220)
	if err != nil {
		return nil, err
	}

	return &FTPClient{Text: tconn}, nil
}

func (c *FTPClient) cmd(expectCode int, format string, args ...interface{}) (int, string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
	return code, msg, err
}

func (c *FTPClient) StartTLS() error {
	_, _, err := c.cmd(234, "AUTH TLS")
	return err
}

func FTPScanner(conn net.Conn, fn InnerFunc) error {
	client, err := NewFTPClient(conn)
	if err != nil {
		return err
	}

	if err := client.StartTLS(); err != nil {
		return err
	}

	if _, err := fn(); err != nil {
		return err
	}

	return nil
}
