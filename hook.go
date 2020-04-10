package spf

import "github.com/miekg/dns"

// Hook allows a caller to intercept the SPF check process at various points
// through it's execution.
type Hook interface {
	Dns(r *dns.Msg, m *dns.Msg, err error) // a dns record was looked up
	Record(record, domain string) // an SPF record is about to be processed
	RecordResult(domain string, result *Result) // an SPF record has completed processing
	Macro(before, after string, err error) // a macro has been expanded
	Mechanism(domain string, index int, mechanism Mechanism, result *Result) // an SPF mechanism has provided a result
	Redirect(target string) // an SPF redirect modifier is about to be executed
}
