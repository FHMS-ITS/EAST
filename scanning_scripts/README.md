# Scanning Scripts

## Installation

1. Install Golang: <https://golang.org/doc/install>
2. Install ZGrab2: <https://github.com/zmap/zgrab2>
3. Copy folders `modules` and `zgrab2_schemas` into the zgrab-root under `$GOPATH/src/github.com/zmap/zgrab2`
4. `cd $GOPATH/src/github.com/zmap/zgrab2`

5. `make`

## Usage

* e.g.: `./zgrab2 -f hosts_in.txt -o results.json imap_buffering error`
* see `./zgrab2 <module> --help` for help on parameters

## IMAP Scanning

### imap_capabilities

Fetches IMAP capabilties before and after STARTTLS on port 143.

Example:

`./zgrab2 -f hosts.txt -o results.json imap_capabilities`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results

Procedure:

1. Connect to host on port 143.
2. Read greeting.
3. Send `CAPABILITY` command
4. Send `ID` command
5. Send `STARTTLS` and transition to TLS if possible (return`no-starttls` otherwise).
6. Send `CAPABILITY` command
7. Send `ID` command
8. Send `LOGOUT` command and wait for server to close the connection (or timeout).

### imap_implicit_tls

Fetches IMAP capabilties for implicit TLS on port 993.

Example:

`./zgrab2 -f hosts.txt -o results.json imap_implicit_tls`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results

Procedure:

1. Connect to host on port 993.
2. Perform TLS Handshake.
3. Read greeting.
4. Send `LOGOUT` command and wait for server to close connection (or timeout).

### imap_buffering_error

Tests an IMAP server for the STARTTLS command injection bug.

Example:

`./zgrab2 -f hosts.txt -o results.json imap_buffering_error`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results

Procedure:

1. Connect to host on port 143.
2. Read greeting.
3. Send `A STARTTLS` and `<random-1> NOOP` in one packet.
4. Transition to TLS if possible.
5. Wait for response to `NOOP`.
   1. If response received: Server is vulnerable.
6. Send `<random-2> LOGOUT` to flush any remaining data.
7. Wait for response. If response contains `<random-1>`, the server accepted the buffered `NOOP`command and is vulnerable to the command injection.
8. Wait for the server to close the connection (or timeout).

Results:

* Indicates whether the target is believed to be vulnerable in `vulnerable` field.

## SMTP Scanning

### smtp_capabilities

Fetches SMTP capabilties before and after STARTTLS.

Example:

`./zgrab2 --f hosts.txt -o results.json smtp_capabilities --scandomain <scandomain> --port 587`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results
* `--scandomain` (or `-d`): DOMAIN to set the scanners own domain (which is advertised in the initial EHLO)
* `--port` (or `-p`): SMTP port to connect to.

Procedure:

1. Connect to host on specified port.
2. Read greeting.
3. Send `EHLO <scannerdomain>` command and read result.
4. Send `HELP` command and read result.
5. Send `STARTTLS` and transition to TLS if possible (return`no-starttls` otherwise).
6. Send `EHLO <scannerdomain>` command and read result.
7. Send `HELP` command.
8. Send `QUIT` command and wait for server to close the connection (or timeout).

### smtp_implicit_tls

Fetches SMTP capabilties before and after STARTTLS.

Example:

`./zgrab2 --f hosts.txt -o results.json smtp_implicit_tls --scandomain <scandomain> --port 587`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results
* `--scandomain` (or `-d`): DOMAIN to set the scanners own domain (which is advertised in the initial EHLO)
* `--port` (or `-p`): SMTP port to connect to.

Procedure:

1. Connect to host on specified port.
2. Perform TLS handshake.
3. Read greeting.
4. Send `EHLO <scannerdomain>` command and read result.
5. Send `HELP` command and read result.
6. Send `QUIT` command and wait for server to close the connection (or timeout).

### smtp_buffering_error

Tests an SMTP server for the STARTTLS command injection bug.

Example:

`./zgrab2 --f hosts.txt -o results.json smtp_implicit_tls --scandomain <scandomain> --port 587`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results
* `--scandomain` (or `-d`): DOMAIN to set the scanners own domain (which is advertised in the initial EHLO)
* `--port` (or `-p`): SMTP port to connect to.

Procedure:

1. Connect to host on specified port.
2. Read greeting.
3. Send `EHLO <scannerdomain>` command and read result.
4. Send `STARTTLS` and `EHLO <scannerdomain>` in one packet.
5. Transition to TLS if possible.
6. Wait for response to `EHLO`.
   1. If response received: Server is vulnerable.
7. Send `QUIT` command to flush any remaining data. 
8. Wait for response. If response contains an `EHLO` response, the server accepted the buffered `EHLO`command and is vulnerable to the command injection.
9. Wait for the server to close the connection (or timeout).

Results:

* Indicates whether the target is believed to be vulnerable in `vulnerable` field.

## POP3 

### pop3_capabilities

Fetches POP3 capabilties before and after STARTTLS.

Example:

`./zgrab2 --f hosts.txt -o results.json pop3_capabilities`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results

Procedure:

1. Connect to host on port 110.
2. Read greeting.
3. Send `CAPA` command and read result.
4. Send `STLS` command and transition to TLS if possible (return`no-starttls` otherwise).
5. Send `CAPA` command and read result.
6. Send `HELP` command.
7. Send `QUIT` command and wait for server to close the connection (or timeout).

### pop3_implicit_tls

Fetches POP3 capabilties for implicit TLS.

Example:

`./zgrab2 --f hosts.txt -o results.json pop3_implicit_tls`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results

Procedure:

1. Connect to host on port 995.
2. Perform TLS handshake.
3. Read greeting.
4. Send `CAPA` command and read result.
5. Send `QUIT` command and wait for server to close the connection (or timeout).

### pop3_buffering_error

Tests a POP3 server for the STARTTLS command injection bug.

Example:

`./zgrab2 -f hosts.txt -o results.json pop3_buffering_error`

Parameters:

* default zgrab parameters
* parameters for the TLS-Handshake
* `--verbose` (or `-v`) to log TLS-Details in the results

Procedure:

1. Connect to host on port 110.
2. Read greeting.
3. Send `STLS` and `CAPA` in one packet.
4. Transition to TLS if possible.
5. Wait for response to `CAPA`.
   1. If response received (via TLS): Server is vulnerable.
6. Send `QUIT` command to flush any remaining data. 
7. Wait for response. If response contains a `CAPA` response, the server accepted the buffered `CAPA` command and is vulnerable to the command injection.
8. Wait for the server to close the connection (or timeout).

Results:

* Indicates whether the target is believed to be vulnerable in `vulnerable` field.
