# Email Analysis Toolkit (EAST)

Artifacts for the USENIX paper ["Why TLS is better without STARTTLS: A Security Analysis of STARTTLS in the Email Context"](https://www.usenix.org/conference/usenixsecurity21/presentation/poddebniak) ([Pre-Print](https://nostarttls.secvuln.info/paper.pdf)) by [Damian Poddebniak](https://github.com/duesee)¹, [Fabian Ising](https://github.com/Murgeye)¹, [Hanno Böck](https://github.com/hannob)², and [Sebastian Schinzel](https://github.com/seecurity)¹. The Fake Mail Server and the Command Injection Tester were peer-reviewed in the [USENIX'21 Call for Artifacts](https://www.usenix.org/conference/usenixsecurity21/call-for-artifacts).

¹ [Münster University of Applied Sciences](https://www.fh-muenster.de/eti/labore_forschung/ts/index.php), 
² Independent Researcher

More information about our STARTTLS research can be found here: https://nostarttls.secvuln.info/

## Where is the Code?

This repository is a landing page. Head over to the ["Email Analysis Toolkit"](https://github.com/Email-Analysis-Toolkit) organization to find the EAST tooling:

* [Fake Mail Server](https://github.com/Email-Analysis-Toolkit/fake-mail-server): a configurable SMTP, POP3, and IMAP testing server.
* [Command Injection Tester](https://github.com/Email-Analysis-Toolkit/command-injection-tester): a simple Python tool to test SMTP, POP3, and IMAP servers for the [command injection vulnerability](https://www.postfix.org/CVE-2011-0411.html) in STARTTLS.
* [Command Injection Scanner](https://github.com/Email-Analysis-Toolkit/command-injection-scanner): zgrab2 modules to perform an IPv4-Internet scan for the command injection in STARTTLS.

## Virtual Machine for Client Testing

In addition to the provided code, we provided a Ubuntu-based VirtualBox VM as a GitHub release to ease client testing. This Virtual Machine contains a nested QEMU Virtual Machine with the Thunderbird Version tested in the paper. For further information, see the GitHub releases.
