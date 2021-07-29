# zschema sub-schema for zgrab2's imap module
# Registers zgrab2-imap globally, and imap with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry
import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

imap_scan_response = SubRecord({
    "result": SubRecord({
        "status": String(doc="the status in which the scan ended (final state: 4)"),
        "vulnerable": String(doc="whether this scan believes the target to be vulnerable"),
        "trace": String(doc="the complete trace of client and server communication"),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

pop3_scan_response = SubRecord({
    "result": SubRecord({
        "status": String(doc="the status in which the scan ended (final state: 4)"),
        "vulnerable": String(doc="whether this scan believes the target to be vulnerable"),
        "trace": String(doc="the complete trace of client and server communication"),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

smtp_scan_response = SubRecord({
    "result": SubRecord({
        "status": String(doc="the status in which the scan ended (final state: 4)"),
        "vulnerable": String(doc="whether this scan believes the target to be vulnerable"),
        "trace": String(doc="the complete trace of client and server communication"),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

smtp_capabilities_scan_response = SubRecord({
    "result": SubRecord({
        "status": String(doc="the status in which the scan ended (final state: 6)"),
        "preTLS": String(doc="the capabilities before STARTTLS"),
        "help": String(doc="the response to the HELP command"),
        "postTLS": String(doc="the capabilities after STARTTLS"),
        "http": String(doc="the response to the HTTP-GET"),
        "trace": String(doc="the complete trace of client and server communication"),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

smtp_explicit_tls_response = SubRecord({
    "result": SubRecord({
        "status": String(doc="the status in which the scan ended (final state: 4)"),
        "capabilities": String(doc="the capabilities in TLS"),
        "trace": String(doc="the complete trace of client and server communication"),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)


zschema.registry.register_schema("zgrab2-imap_buffering_error", imap_scan_response)
zgrab2.register_scan_response_type("imap_buffering_error", imap_scan_response)

zschema.registry.register_schema("zgrab2-pop3_buffering_error", pop3_scan_response)
zgrab2.register_scan_response_type("pop3_buffering_error", pop3_scan_response)

zschema.registry.register_schema("zgrab2-smtp_buffering_error", smtp_scan_response)
zgrab2.register_scan_response_type("smtp_buffering_error", smtp_scan_response)

zschema.registry.register_schema("zgrab2-smtp_capabilities", smtp_capabilities_scan_response)
zgrab2.register_scan_response_type("smtp_capabilities", smtp_capabilities_scan_response)

zschema.registry.register_schema("zgrab2-smtp_explicit_tls", smtp_explicit_tls_response)
zgrab2.register_scan_response_type("smtp_explicit_tls", smtp_explicit_tls_response)
