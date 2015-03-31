package scanners

import (
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

type SMTPClient struct {
	Text *textproto.Conn

	ext map[string]string
}

func NewSMTPClient(conn net.Conn) *SMTPClient {
	tconn := textproto.NewConn(conn)
	_, msg, err := tconn.ReadCodeLine(220)
	fmt.Println("EHLO", msg, err)
	return &SMTPClient{Text: tconn}
}

func (c *SMTPClient) Ehlo(host string) error {
	_, msg, err := c.cmd(250, "EHLO %s", host)
	fmt.Println("EHLO", msg, err)

	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		extList = extList[1:]
		for _, line := range extList {
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				ext[args[0]] = args[1]
			} else {
				ext[args[0]] = ""
			}
		}
	}
	c.ext = ext
	return err
}

func (c *SMTPClient) HasTLSSupport() bool {
	_, supported := c.ext["STARTTLS"]
	return supported
}

func (c *SMTPClient) StartTLS() error {
	_, msg, err := c.cmd(220, "STARTTLS")
	fmt.Println("STARTTLS", msg, err)
	return err
}

func (c *SMTPClient) cmd(expectCode int, format string, args ...interface{}) (int, string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
	return code, msg, err
}

func SMTPScanner(conn net.Conn, fn InnerFunc) error {
	client := NewSMTPClient(conn)

	if err := client.Ehlo("sslscanner.com"); err != nil {
		return err
	}

	if !client.HasTLSSupport() {
		// warning, smtp has no ssl support
		return nil
	}

	if err := client.StartTLS(); err != nil {
		return err
	}

	if _, err := fn(); err != nil {
		return err
	}

	return nil
}
