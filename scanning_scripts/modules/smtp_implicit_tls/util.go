package smtp_implicit_tls

import (
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Regex for a full smtp-response
var lineEndRegex = regexp.MustCompile("(.*\r\n)*\\d{3} [^\r\n]*(\r\n)$")
var blackListRegex = regexp.MustCompile("(?m)^(554|550|521|541|421|504|553)\\s")

const readBufferSize int = 0x10000

// Connection wraps the state and access to the SMTP connection.
type Connection struct {
	Conn net.Conn
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
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}
