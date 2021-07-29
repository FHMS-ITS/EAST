package imap_capabilities

import (
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Regex for a full tagged imap-response
// Zero or more untagged responses + One tagged response
var taggedResponseRegex = regexp.MustCompile("(?m)(\\* .*\r\n)*(^[^\\*]* .*\r\n)")

// Regex for a full untagged imap-response
var untaggedRegex = regexp.MustCompile("\\*.*\r\n")

const readBufferSize int = 0x10000

// Connection wraps the state and access to the imap connection.
type Connection struct {
	Conn net.Conn
}

func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, taggedResponseRegex)
	if n == 0 {
		return "", err
	}
	return string(ret[0:n]), err
}

func (conn *Connection) ReadUntagged() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, untaggedRegex)
	if n == 0 {
		return "", err
	}
	return string(ret[0:n]), err
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}
