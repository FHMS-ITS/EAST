#! /usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2021 FH Münster
# Developed by Samson Umezulike and Fabian Ising
#
# Contact: starttls@fh-muenster.de
#
# Distributed under terms of the MIT license.

import select
import sys
import os
import socket
import ssl
import logging
import argparse
from enum import Enum
from pathlib import Path
import random
from typing import Callable, Union

Protocol = Enum("Protocol", ("IMAP", "POP3", "SMTP"))

# We need a custom TRACE level for logging
TRACE = 15
logging.addLevelName(TRACE, 'TRACE')

default_ports = {
    Protocol.IMAP: 143,
    Protocol.POP3: 110,
    Protocol.SMTP: 587
}

DEFAULT_LOGDIR = "./logs"
DEFAULT_COMMENT = "commandinjectiontester"
DEFAULT_TIMEOUT = 2


def red(string: str) -> str:
    return '\033[31m' + string + '\033[0m'


def green(string: str) -> str:
    return '\033[32m' + string + '\033[0m'


class ServerTest:

    def __init__(self, protocol: Protocol, logging_level, hostname: str, port: int, **kwargs):
        """
        Create a new Servertest object for a specific protocol and port
        """
        self.protocol = protocol
        self.logging_level = logging_level
        self.hostname = hostname
        self.port = port or default_ports.get(protocol)
        self.logdir = kwargs.get("logdir", None) or DEFAULT_LOGDIR
        self.comment = kwargs.get("comment", None) or DEFAULT_COMMENT
        self.timeout = kwargs.get("timeout", None) or DEFAULT_TIMEOUT

    def recv_from_ssl(self, sock: ssl.SSLSocket) -> bytes:
        """
        Receive data from a TLS socket using select
        """
        sock.setblocking(False)
        data = b""
        while True:
            r, w, e = select.select([sock], [], [], self.timeout)
            if sock in r:
                try:
                    new_data = sock.recv(1024)
                except ssl.SSLError as e:
                    if e.errno != ssl.SSL_ERROR_WANT_READ:
                        raise
                    continue
                if len(new_data) == 0:
                    break
                data += new_data
                data_left = sock.pending()
                while data_left:
                    data += sock.recv(data_left)
                    data_left = sock.pending()
            else:
                break
        return data

    def _recv_multiple_segments(self, sock, logger) -> bytes:
        """
        Allows recv of multiple segments, e.g., if a server uses send(line1); send(line2); ...
        """
        limit = 5
        resp = b""
        count = 0
        while count < limit:
            try:
                r, w, e = select.select([sock], [], [], self.timeout)
                if sock in r:
                    resp += sock.recv(1024)
                    count += 1
                else:
                    return resp
            except socket.timeout:
                break
            except ConnectionResetError:
                logger.warning("Connection was reset while reading from socket. Further analysis might be necessary.")
                break
        return resp

    def _sanity_test(self, logger: logging.Logger, context: ssl.SSLContext, **kwargs):
        """
        Check for general errors with a sanity check.
        pretls: Commands to send before transitioning to TLS.
        posttls: Commands to send after transitioning to TLS.
        """
        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                logger.info("Sanity test...")
                try:
                    resp = self._recv_multiple_segments(sock, logger)
                    log_trace(logger, resp, incoming=True)
                    for payload in kwargs.get("pretls"):
                        log_trace(logger, payload, incoming=False)
                        sock.send(payload.encode())
                        resp = self._recv_multiple_segments(sock, logger)
                        log_trace(logger, resp, incoming=True)
                    with context.wrap_socket(sock=sock, server_hostname=self.hostname) as ssock:
                        logger.debug("<----- TLS Handshake ----->")
                        for payload in kwargs.get("posttls"):
                            ssock.send(payload.encode())
                            log_trace(logger, payload, incoming=False)
                            resp = self.recv_from_ssl(ssock)
                            log_trace(logger, resp, incoming=True)
                except socket.timeout as e:
                    msg = f"Sanity test failed. The connection to {self.hostname}:{self.port} timed out."
                    logger.error(red(msg))
                    return False
                except ssl.SSLError as e:
                    msg = f"Sanity test failed. Could not perform TLS handshake with {self.hostname}:{self.port}."
                    logger.error(red(msg))
                    return False
                else:
                    logger.info(green("Sanity test done"))
                    return True
        except socket.timeout as e:
            msg = f"Sanity test failed. The connection to {self.hostname}:{self.port} ran into a timeout."
            logger.error(red(msg))
            return False
        except ConnectionRefusedError as e:
            msg = f"Sanity test failed. The connection to {self.hostname}:{self.port} was refused."
            logger.error(red(msg))
            return False
        except socket.error as e:
            msg = f"Sanity test failed. The connection to {self.hostname}:{self.port} ran into an error."
            logger.exception(red(msg))
            return False

    def _injection_test(self, logger: logging.Logger, context: ssl.SSLContext, **kwargs) -> bool:
        """
        Check for the command injection vulnerability.
        pretls: Commands to send before transitioning to TLS.
        test: fn(resp)->bool to check if the server is vulnerable from the first server response sent after the transition to TLS.
        posttls: Commands to send after transitioning to TLS.
        command: Command to send inside the TLS session if no response was received before the timeout.

        returns True if sanity test was successful, false otherwise.
        """
        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                logger.info("Testing for command injection...")
                resp = self._recv_multiple_segments(sock, logger)
                log_trace(logger, resp, incoming=True)
                pretls = kwargs.get("pretls")
                for payload in pretls:
                    log_trace(logger, payload, incoming=False, formatter=red if payload == pretls[-1] else None)
                    sock.send(payload.encode())
                    resp = self._recv_multiple_segments(sock, logger)
                    log_trace(logger, resp, incoming=True)
                try:
                    with context.wrap_socket(sock=sock, server_hostname=self.hostname) as ssock:
                        logger.debug("<----- TLS Handshake ----->")
                        ssock.setblocking(False)

                        resp = self.recv_from_ssl(ssock)
                        if resp:
                            log_trace(logger, resp, incoming=True, formatter=red)
                            if kwargs.get("test")(resp):
                                logger.warning(red("Command injection here!"))
                            else:
                                logger.warning(red("Probable command injection. Response looks different than expected."))

                        else:
                            logger.debug("No response in encrypted context, trying real command now ...")
                            payload = kwargs.get("command")
                            ssock.send(payload.encode())
                            log_trace(logger, payload, incoming=False)
                            try:
                                resp = self.recv_from_ssl(ssock)
                                if resp:
                                    if kwargs.get("test")(resp):
                                        log_trace(logger, resp, incoming=True, formatter=red)
                                        logger.warning(red("Possible command injection here."))
                                    else:

                                        log_trace(logger, resp, incoming=True)
                                        logger.info(green("Probably no command injection here!"))
                                else:
                                    raise Exception
                            except Exception as e:
                                msg = f"Server unresponsive: Possible command injection here!\nFurther analysis needed."
                                logger.warning(red(msg))

                except OSError as e:
                    logger.info(green("TLS handshake failed - Server probably closed the connection!"))

        except ConnectionRefusedError as e:
            msg = f"Injection test failed. The connection to {self.hostname}:{self.port} was refused."
            logger.error(red(msg))
            return

        except socket.error as e:
            msg = f"Injection test failed. The connection to {self.hostname}:{self.port} ran into an error."
            logger.exception(red(msg))
            return False

    def test_imap_server(self, logger: logging.Logger, context: ssl.SSLContext):
        result = self._sanity_test(logger=logger, context=context,
                                   pretls=[f"A STARTTLS\r\n"],
                                   posttls=["B LOGOUT\r\n"])

        if result:
            injection_tag = get_random_tag()
            self._injection_test(logger=logger, context=context,
                                 pretls=[f"A STARTTLS\r\n{injection_tag} NOOP\r\n"],
                                 command="C NOOP\r\n",
                                 test=lambda r: injection_tag.encode() in r)

    def test_pop3_server(self, logger: logging.Logger, context: ssl.SSLContext):
        result = self._sanity_test(logger=logger, context=context,
                                   pretls=[f"STLS\r\n"],
                                   posttls=["QUIT\r\n"])
        if result:
            self._injection_test(logger=logger, context=context,
                                 pretls=[f"STLS\r\nCAPA\r\n"],
                                 command="USER user\r\n",
                                 test=lambda r: b"TOP" in r or b"-ERR" in r)

    def test_smtp_server(self, logger: logging.Logger, context: ssl.SSLContext):
        result = self._sanity_test(logger=logger, context=context,
                                   pretls=[f"EHLO {self.comment}\r\n", "NOOP\r\n", "STARTTLS\r\n"],
                                   posttls=["QUIT\r\n"])
        if result:
            self._injection_test(logger=logger, context=context,
                                 pretls=[f"EHLO {self.comment}\r\n", f"STARTTLS\r\nEHLO commandinjectiontester\r\n"],
                                 command=f"FAKE {self.comment}\r\n",
                                 test=lambda r: b"250" in r)

    def test_server(self):
        logger = self.get_logger()
        context = get_ssl_context()
        logger.info(f"Testing {self.protocol.name} server at {self.hostname}:{self.port}")
        logger.debug(f"Logdir: {self.logdir}, Comment: {self.comment}, Timeout: {self.timeout}")

        {Protocol.IMAP: self.test_imap_server,
         Protocol.SMTP: self.test_smtp_server,
         Protocol.POP3: self.test_pop3_server}.get(self.protocol)(logger, context)

    def get_logger(self) -> logging.Logger:
        proto = self.protocol
        logger = logging.getLogger(f"{self.hostname}_{proto.name}")
        sh = logging.StreamHandler(sys.stdout)
        Path(self.logdir).mkdir(exist_ok=True)
        fh = logging.FileHandler(f"{self.logdir}{os.sep}{self.hostname}_{proto.name}.log")
        formatter = logging.Formatter(f"{proto.name}: %(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        sh.setFormatter(formatter)
        fh.setFormatter(formatter)
        logger.addHandler(sh)
        logger.addHandler(fh)
        logger.setLevel(self.logging_level)
        return logger


def log_trace(logger: logging.Logger, content: Union[str, bytes], incoming: bool, formatter: Callable[[str], str] = None):
    if type(content) == bytes:
        content = content.decode()
    lines = [li for li in content.split("\n") if li]
    for line in lines:
        message = f"{'S' if incoming else 'C'}: {line.rstrip()}"
        if formatter:
            message = formatter(message)
        logger.log(level=TRACE, msg=message)


def get_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.options = ssl.OP_ALL
    return context


def get_random_tag() -> str:
    return "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5))


def parse_args():
    parser = argparse.ArgumentParser(description='Check a server for the STARTTLS command injection bug')
    parser.add_argument("hostname", help="Host to check", type=str)
    parser.add_argument("--imap-port", "-i", help="IMAP Port to check", type=int)
    parser.add_argument("--pop3-port", "-p", help="POP3 Port to check", type=int)
    parser.add_argument("--smtp-port", "-s", help="SMTP Port to check", type=int)
    parser.add_argument("--imap", help="Use the IMAP protocol", action="store_const", const=Protocol.IMAP)
    parser.add_argument("--pop3", help="Use the POP3 protocol", action="store_const", const=Protocol.POP3)
    parser.add_argument("--smtp", help="Use the SMTP protocol", action="store_const", const=Protocol.SMTP)
    parser.add_argument('--quiet', '-q', action='store_true')
    parser.add_argument("--logdir", "-l", help="Path to log directory, defaults to ./logs", type=str)
    parser.add_argument("--comment", "-c", help="Comment to include in test commands", type=str)
    parser.add_argument("--timeout", "-t", help=f"Timeout for sockets, defaults to {DEFAULT_TIMEOUT}s", type=int)
    parser.add_argument("--nocolor", help=f"Deactivate color highlighting", action="store_true")

    args = parser.parse_args(sys.argv[1:])

    protocols = list(filter(None, [args.imap, args.pop3, args.smtp]))
    logging_level = logging.INFO if args.quiet else logging.DEBUG

    if not protocols:
        print("At least one of --imap, --pop3, --smtp is required")

    if args.nocolor:
        global red, green
        red = green = lambda s: s

    for protocol in protocols:
        port = None
        if protocol == Protocol.IMAP:
            port = args.imap_port
        elif protocol == Protocol.POP3:
            port = args.pop3_port
        elif protocol == Protocol.SMTP:
            port = args.smtp_port
        st = ServerTest(protocol=protocol, logging_level=logging_level, hostname=args.hostname, port=port,
                        logdir=args.logdir, comment=args.comment, timeout=args.timeout)
        st.test_server()
        print()


if __name__ == '__main__':
    parse_args()
