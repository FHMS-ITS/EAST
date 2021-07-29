package imap_buffering_error

import (
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
	"math/rand"
	"time"
)

// Regex for a full tagged imap-response
// Zero or more untagged responses + One tagged response
var taggedResponseRegex = regexp.MustCompile("(?m)(\\* .*\r\n)*(^[^\\*]* .*\r\n)")

// Regex for a full untagged imap-response
var untaggedRegex = regexp.MustCompile("\\*.*\r\n")

var lineRegex = regexp.MustCompile(".*\r\n")

const readBufferSize int = 0x10000

// Connection wraps the state and access to the imap connection.
type Connection struct {
	Conn net.Conn
}

func (conn *Connection) ReadLine() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, lineRegex)
	if n == 0 {
		return "", err
	}
	return string(ret[0:n]), err
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

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return StringWithCharset(length, charset)
}
