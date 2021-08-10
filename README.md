# Email Analysis Toolkit (EAST)

This repository contains information on the artifacts for the USENIX paper ["Why TLS is better without STARTTLS: A Security Analysis of STARTTLS in the Email Context"](https://www.usenix.org/conference/usenixsecurity21/presentation/poddebniak) by Damian Poddebniak¹, Fabian Ising¹, Hanno Böck², and Sebastian Schinzel¹. The Fake Mail Server and the Command Injection Tester were peer-reviewed in the [USENIX'21 Call for Artifacts](https://www.usenix.org/conference/usenixsecurity21/call-for-artifacts).

¹ Münster University of Applied Sciences        ² Independent Researcher

More information about our STARTTLS research can be found here:

 * https://nostarttls.secvuln.info/

## Where is the Code?

This repository serves as a landing page now. Please head over to the ["Email Analysis Toolkit"](https://github.com/Email-Analysis-Toolkit) organization to find your desired tool:

* [Fake Mail Server](https://github.com/Email-Analysis-Toolkit/fake-mail-server): a configurable SMTP, POP3, and IMAP testing server.
* [Command Injection Tester](https://github.com/Email-Analysis-Toolkit/command-injection-tester): a simple Python tool to test SMTP, POP3, and IMAP servers for the [command injection vulnerability](https://www.postfix.org/CVE-2011-0411.html) in STARTTLS.
* [Command Injection Scanner](https://github.com/Email-Analysis-Toolkit/command-injection-scanner): zgrab2 modules to perform an IPv4-Internet scan for the command injection in STARTTLS.

## Virtual Machine for Client Testing

In addition to the provided code, we provided a Ubuntu-based VirtualBox VM as a GitHub release to ease client testing. This Virtual Machine contains a nested QEMU Virtual Machine with the Thunderbird Version tested in the paper. For further information, see the GitHub releases.
