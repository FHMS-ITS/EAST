package modules

import (
	"github.com/zmap/zgrab2/modules/imap_buffering_error"
	"github.com/zmap/zgrab2/modules/imap_capabilities"
	"github.com/zmap/zgrab2/modules/imap_implicit_tls"
	"github.com/zmap/zgrab2/modules/pop3_buffering_error"
	"github.com/zmap/zgrab2/modules/pop3_capabilities"
	"github.com/zmap/zgrab2/modules/pop3_implicit_tls"
	"github.com/zmap/zgrab2/modules/smtp_buffering_error"
	"github.com/zmap/zgrab2/modules/smtp_capabilities"
	"github.com/zmap/zgrab2/modules/smtp_cross_protocol"
	"github.com/zmap/zgrab2/modules/smtp_implicit_tls"
	"github.com/zmap/zgrab2/modules/smtp_session_fixation"
)

func init() {
	imap_buffering_error.RegisterModule()
	imap_capabilities.RegisterModule()
	imap_implicit_tls.RegisterModule()
	pop3_implicit_tls.RegisterModule()
	pop3_buffering_error.RegisterModule()
	pop3_capabilities.RegisterModule()
	smtp_buffering_error.RegisterModule()
	smtp_capabilities.RegisterModule()
	smtp_session_fixation.RegisterModule()
	smtp_cross_protocol.RegisterModule()
	smtp_implicit_tls.RegisterModule()
}
