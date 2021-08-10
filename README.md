# EAST

This repository contains information on the artifacts for the USENIX paper "Why TLS is better without STARTTLS: A Security Analysis of STARTTLS in the Email Context" by Damian Poddebniak¹, Fabian Ising¹, Hanno Böck², and Sebastian Schinzel¹. Very similar versions of the Command Injection Tester and the Fake Mail Server were peer-reviewed in the USENIX'21 Call for Artifacts.

¹ Münster University of Applied Sciences        ² Independent Researcher

More information about our STARTTLS research can be found here:

 * https://nostarttls.secvuln.info/

## Contents of this Repository

Note: We have split the artifacts into three independent repositories to allow for easier handling of contributions and the usage of continuous integration.

We provide three components, each of which comes with its own README in the corresponding repository.

1. The [Fake Mail Server](https://github.com/Email-Analysis-Toolkit/fake-mail-server), a custom-built and configurable SMTP, POP3, and IMAP server. The Fake Mail Server was instrumental in the client evaluation part of our paper.
2. The [Command Injection Tester](https://github.com/Email-Analysis-Toolkit/command-injection-tester), a Python Script for testing SMTP, POP3, and IMAP servers for the [command injection vulnerability](https://www.postfix.org/CVE-2011-0411.html) in STARTTLS.
3. [Scanning Scripts](https://github.com/Email-Analysis-Toolkit/command-injection-scanner), which were used to perform IPv4-Internet scans for servers vulnerable to the Command Injection issue.

## Virtual Machine for Client Testing

In addition to the provided code, we provided a Ubuntu-based VirtualBox VM as a GitHub release to ease client testing. This Virtual Machine contains a nested QEMU Virtual Machine with the Thunderbird Version tested in the paper. For further information, see the GitHub releases.
