package pop3_implicit_tls

import (
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Regex for a full pop3-response
var lineEndRegex = regexp.MustCompile("(.*\r\n)+")
var CAPARegex = regexp.MustCompile("(.*\r\n)*(\\.\r\n)")

const readBufferSize int = 0x10000

// Connection wraps the state and access to the SMTP connection.
type Connection struct {
	Conn net.Conn
}

func (conn *Connection) ReadCAPAResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, CAPARegex)
	if n == 0 {
		return "", err
	}
	return string(ret[0:n]), err
}

func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, lineEndRegex)
	if n == 0 {
		return "", err
	}
	return string(ret[0:n]), err
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
// This function is specific for the CAPA command
func (conn *Connection) SendCommandCAPA(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadCAPAResponse()
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}
