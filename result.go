package spf

import (
	"fmt"
	"net"
)

//go:generate enumer -type ResultType -transform=snake

// Result types, from RFC 7208
// 2.6.1.  None
//
//  A result of "none" means either (a) no syntactically valid DNS domain
//  name was extracted from the SMTP session that could be used as the
//  one to be authorized, or (b) no SPF records were retrieved from
//  the DNS.
//
// 2.6.2.  Neutral
//
//  A "neutral" result means the ADMD has explicitly stated that it is
//  not asserting whether the IP address is authorized.
//
// 2.6.3.  Pass
//
//  A "pass" result is an explicit statement that the client is
//  authorized to inject mail with the given identity.
//
// 2.6.4.  Fail
//
//  A "fail" result is an explicit statement that the client is not
//  authorized to use the domain in the given identity.
//
// 2.6.5.  Softfail
//
//  A "softfail" result is a weak statement by the publishing ADMD that
//  the host is probably not authorized.  It has not published a
//  stronger, more definitive policy that results in a "fail".
//
// 2.6.6.  Temperror
//
//  A "temperror" result means the SPF verifier encountered a transient
//  (generally DNS) error while performing the check.  A later retry may
//  succeed without further DNS operator action.
//
// 2.6.7.  Permerror
//
//  A "permerror" result means the domain's published records could not
//  be correctly interpreted.  This signals an error condition that
//  definitely requires DNS operator intervention to be resolved.

// ResultType is the overall SPF result from checking a message.
type ResultType int

const (
	None ResultType = iota
	Neutral
	Pass
	Fail
	Softfail
	Temperror
	Permerror
)

// Result is all the information gathered during checking SPF for a message.
type Result struct {
	Type        ResultType
	Error       error
	DNSQueries  int
	VoidLookups int
	Explanation string
	UsedHelo    bool
	ip          net.IP
	sender      string
	helo        string
	c           *Checker
}

func (r *Result) String() string {
	return r.Type.String()
}

// AuthenticationResults displays a Result as an RFC 8601
// Authentication-Results: header
func (r *Result) AuthenticationResults() string {
	if r.UsedHelo {
		return fmt.Sprintf("%s; spf=%s smtp.helo=%s", r.c.Hostname, r.Type.String(), r.helo)
	}
	return fmt.Sprintf("%s; spf=%s smtp.mailfrom=%s", r.c.Hostname, r.Type.String(), r.sender)
}
