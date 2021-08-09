package smtp_capabilities

import (
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {

	// Trace is the complete communication between client and server
	Trace []string `json:"trace"`

	// Status is the step, the execution of the Scan ended in (used for debug)
	Status int `json:"status,omitempty"`

	// PreTLS is the targets response to EHLO in plain (pre-tls) state
	PreTLS string `json:"preTLS,omitempty"`

	// Help is the targets response to the HELP command before tls
	PreTLSHelp string `json:"preTLShelp,omitempty"`

	// PostTLS is the targets response to EHLO in encrypted (post-tls) state
	PostTLS string `json:"postTLS,omitempty"`

	// Help is the targets response to the HELP command in encrypte (tls) state
	PostTLSHelp string `json:"PosTLShelp,omitempty"`

	// HTTP is the targets response to the HTTP-Get (if any)
	//HTTP string `json:"http,omitempty"`

	// TLSLog is the standard TLS log
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the IMAP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	// ScannerDomain sets the advertised own domain name
	ScannerDomain string `short:"d" long:"scandomain" description:"The own Domain (advertised in EHLO command)"`

	// Verbose indicates that there should be more verbose logging.
	Verbose bool `short:"v" long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("smtp_capabilities", "fetch smtp capabilities", module.Description(), 25, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetches SMTP Capabilities before and after STARTTLS"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return "todo"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "smtp"
}

// Scan performs the SMTP scan.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	result := &ScanResults{}
	singleReadTimeout := time.Second * 5

	// Step 0
	// Connect to Target
	c, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer c.Close()
	conn := Connection{Conn: c}
	result.Status = 0

	// Read greeting
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err := conn.ReadResponse()
	if err != nil {
		status := zgrab2.TryGetScanStatus(err)
		// We interpret a missing greeting as a non-smtp service
		if status == zgrab2.SCAN_IO_TIMEOUT {
			status = zgrab2.ScanStatus("no-smtp")
		}
		return status, result, err
	}

	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))

	// Abort if we are blacklisted :(
	if blackListRegex.MatchString(ret) {
		return zgrab2.ScanStatus("blacklisted"), result, nil
	}

	// Set advertised own Domain
	scannerDomain := scanner.config.ScannerDomain
	if scannerDomain == "" {
		scannerDomain = "SCAN"
	}

	// Step 1
	// Send EHLO-Command to initiate SMTP-Session and read pre-TLS-capabilities
	command := "EHLO " + scannerDomain
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.PreTLS = ret
	result.Status++

	// Abort if we are blacklisted :(
	if blackListRegex.MatchString(ret) {
		return zgrab2.ScanStatus("blacklisted"), result, nil
	}

	// Step 2
	// Send HELP Command
	command = "HELP"
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.PreTLSHelp = ret
	result.Status++

	// Step 3
	// Send STARTTLS
	command = "STARTTLS"
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.Status++

	// Abort if target didnt "OK" the STARTTLS
	if !strings.HasPrefix(ret, "220") {
		return zgrab2.ScanStatus("no-starttls"), result, nil
	}

	// Step 4
	// TLS - Handshake
	result.Trace = append(result.Trace, "-- TLS Handshake --")
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(conn.Conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	// Log TLS details if set on verbose
	if scanner.config.Verbose {
		result.TLSLog = tlsConn.GetLog()
	}
	err = tlsConn.Handshake()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	conn.Conn = tlsConn
	result.Status++

	// Step 5
	// Send a another EHLO, to read post-TLS-capabilities
	command = "EHLO " + scannerDomain
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	result.Trace = append(result.Trace, "C: "+command)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.PostTLS = ret
	result.Status++

	// Step 6
	// Send HELP Command
	command = "HELP"
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.PostTLSHelp = ret
	result.Status++

	// Send QUIT Command, but don't really care about errors here ...
	command = "QUIT"
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	if ret != "" {
		result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	}
	if err == nil {
		conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
		ret, err = conn.ReadResponse()
		if ret != "" {
			result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
		}
		if err != nil {
			status := zgrab2.TryGetScanStatus(err)
			if status == zgrab2.SCAN_IO_TIMEOUT {
				result.Trace = append(result.Trace, "-- Connection closed --")
			}
		}
	} else {
		status := zgrab2.TryGetScanStatus(err)
		if status == zgrab2.SCAN_IO_TIMEOUT {
			result.Trace = append(result.Trace, "-- Connection closed --")
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
