package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/miekg/dns"
	"strings"
)

// DefaultDNSLimit is the maximum number of SPF terms that require DNS resolution to
// allow before returning a failure.
const DefaultDNSLimit = 10

// DefaultMXAddressLimit is the maximum number of A or AAAA requests to allow while
// evaluating each "mx" mechanism before returning a failure.
const DefaultMXAddressLimit = 10

// DefaultVoidQueryLimit is the maximum number of DNS queries that return no records
// to allow before returning a failure.
const DefaultVoidQueryLimit = 2

// DefaultPtrAddressLimit is the limit on how many PTR records will be used when
// evaluating a "ptr" mechanism or a "%{p}" macro.
const DefaultPtrAddressLimit = 10

// Checker holds all the configuration and limits for checking SPF records.
type Checker struct {
	Resolver        Resolver // used to resolve all DNS queries
	DNSLimit        int      // maximum number of DNS-using mechanisms
	MXAddressLimit  int      // maximum number of hostnames in an "mx" mechanism
	VoidQueryLimit  int      // maximum number of empty DNS responses
	PtrAddressLimit int      // use only this many PTR responses
	Hostname        string   // the hostname of the machine running the check
	Hook            Hook     // instrumentation hooks
}

// NewChecker creates a new Checker with sensible defaults.
func NewChecker() *Checker {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	return &Checker{
		Resolver:        &DefaultResolver{},
		DNSLimit:        DefaultDNSLimit,
		MXAddressLimit:  DefaultMXAddressLimit,
		VoidQueryLimit:  DefaultVoidQueryLimit,
		PtrAddressLimit: DefaultPtrAddressLimit,
		Hostname:        hostname,
	}
}

// DefaultChecker is the Checker that will be used by the package level
// spf.Check function.
var DefaultChecker *Checker

// Check checks SPF policy for a message using both smtp.mailfrom and smtp.helo.
func Check(ctx context.Context, ip net.IP, mailFrom string, helo string) (ResultType, string) {
	if DefaultChecker == nil {
		DefaultChecker = NewChecker()
	}
	result := DefaultChecker.SPF(ctx, ip, mailFrom, helo)
	return result.Type, result.Explanation
}

// SPF checks SPF policy for a message using both smtp.mailfrom and smtp.helo.
func (c *Checker) SPF(ctx context.Context, ip net.IP, mailFrom string, helo string) Result {
	var result Result
	if helo != "" {
		result = Result{
			Type:   None,
			ip:     ip,
			sender: mailFrom,
			helo:   helo,
			c:      c,
		}
		r := c.checkHost(ctx, &result, dns.Fqdn(helo), false, false)
		result.Type = r
		if r != None && r != Neutral {
			result.UsedHelo = true
			return result
		}
	}
	if mailFrom != "" {
		result = Result{
			Type:   None,
			ip:     ip,
			sender: mailFrom,
			helo:   helo,
			c:      c,
		}
		at := strings.LastIndex(mailFrom, "@")
		r := c.checkHost(ctx, &result, dns.Fqdn(mailFrom[at+1:]), false, false)
		result.Type = r
	}
	return result
}

// CheckHost implements the SPF check_host() function for a given domain.
func (c *Checker) CheckHost(ctx context.Context, ip net.IP, domain, sender string, helo string) Result {
	result := Result{
		Type:   None,
		ip:     ip,
		sender: sender,
		helo:   helo,
		c:      c,
	}

	result.Type = c.checkHost(ctx, &result, domain, false, false)
	return result
}

// Anything not 7 bit ascii or any control character
var invalidCharRe = regexp.MustCompile(`[^ -~]`)

func (c *Checker) checkHost(ctx context.Context, result *Result, domain string, include bool, redirect bool) ResultType {
	r := c.checkHostCore(ctx, result, domain, include, redirect)
	if c.Hook != nil {
		c.Hook.RecordResult(domain, result)
	}
	return r
}

// checkHost does the actual RFC 7208 check_host work
func (c *Checker) checkHostCore(ctx context.Context, result *Result, domain string, include bool, redirect bool) ResultType {
	// 4.3 Initial Processing (RFC 7208)
	//  If the <domain> is malformed (e.g., label longer than 63 characters,
	//	zero-length label not at the end, etc.) or is not a multi-label
	//  domain name, or if the DNS lookup returns "Name Error" (RCODE 3, also
	//  known as "NXDOMAIN" [RFC2308]), check_host() immediately returns the
	//  result "none".

	if _, valid := dns.IsDomainName(domain); !valid {
		result.Error = errors.New("invalid domain")
		return None
	}

	if !dns.IsFqdn(domain) {
		result.Error = errors.New("domain not fully qualified")
		return None
	}

	// 4.3 Initial Processing (RFC 7208)
	//  If the <sender> has no local-part, substitute the string "postmaster"
	//  for the local-part.
	if !strings.Contains(result.sender, "@") {
		result.sender = "postmaster@" + result.sender
	}
	if strings.HasPrefix(result.sender, "@") {
		result.sender = "postmaster" + result.sender
	}

	// 4.6.4.  DNS Lookup Limits (RFC 7208)
	//
	//  Some mechanisms and modifiers (collectively, "terms") cause DNS
	//  queries at the time of evaluation, and some do not.  The following
	//  terms cause DNS queries: the "include", "a", "mx", "ptr", and
	//  "exists" mechanisms, and the "redirect" modifier.  SPF
	//  implementations MUST limit the total number of those terms to 10
	//  during SPF evaluation, to avoid unreasonable load on the DNS.  If
	//  this limit is exceeded, the implementation MUST return "permerror".
	result.DNSQueries++
	if result.DNSQueries > c.DNSLimit {
		result.Error = fmt.Errorf("limit of %d dns queries exceeded", c.DNSLimit)
		return Permerror
	}
	record, resultType, err := c.getSPFRecord(ctx, domain)
	if err != nil {
		result.Error = err
		return resultType
	}
	if c.Hook != nil {
		c.Hook.Record(record, domain)
	}

	if record == "" {
		if redirect {
			return Permerror
		}
		return resultType
	}

	badChar := invalidCharRe.FindString(record)
	if badChar != "" {
		result.Error = fmt.Errorf("invalid character %q", badChar[0])
		return Permerror
	}

	mechanisms, err := ParseSPF(record)
	if err != nil {
		result.Error = err
		return Permerror
	}
	for i, mechanism := range mechanisms.Mechanisms {
		resultType, err = mechanism.Evaluate(ctx, result, domain)
		result.Type = resultType
		if c.Hook != nil {
			c.Hook.Mechanism(domain, i, mechanism, result)
		}
		if result.DNSQueries > c.DNSLimit {
			result.Error = fmt.Errorf("limit of %d dns queries exceeded", c.DNSLimit)
			return Permerror
		}
		if resultType != None {
			result.Error = err
			if err == nil && !include && resultType == Fail && mechanisms.Exp != "" {
				target, err := c.ExpandDomainSpec(ctx, mechanisms.Exp, result, domain, false)
				if err != nil {
					result.Error = err
					return Permerror
				}
				if !validDomainName(target) {
					return Permerror
				}
				r := &dns.Msg{}
				r.SetQuestion(target, dns.TypeTXT)
				m, err := c.resolve(ctx, r)
				if err == nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) == 1 {
					txt, ok := m.Answer[0].(*dns.TXT)
					if ok {
						result.Explanation, _ = c.ExpandMacro(ctx, strings.Join(txt.Txt, ""), result, domain, true)
					}
				}
			}
			return resultType
		}
	}

	// Fell off the end of the record
	if mechanisms.Redirect != "" {
		if c.Hook != nil {
			c.Hook.Redirect(mechanisms.Redirect)
		}
		target, err := c.ExpandDomainSpec(ctx, mechanisms.Redirect, result, domain, false)

		if err != nil {
			return Permerror
		}
		if !validDomainName(target) {
			return Permerror
		}

		return c.checkHost(ctx, result, dns.Fqdn(target), false, true)
	}
	return Neutral
}

func (c *Checker) resolve(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	m, err := c.Resolver.Resolve(ctx, r)
	if c.Hook != nil {
		c.Hook.Dns(r, m, err)
	}
	return m, err
}

// SPFRecord holds an SPF record parsed from a single DNS TXT record.
type SPFRecord struct {
	Mechanisms     []Mechanism
	Exp            string
	Redirect       string
	OtherModifiers []string
}

//   modifier         = redirect / explanation / unknown-modifier
//   unknown-modifier = name "=" macro-string
//                      ; where name is not any known modifier
//
//   name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
var modifierRe = regexp.MustCompile(`^((?i)[a-z][a-z0-9_.-]*)=(.*)`)

// ParseSPF parses the text of an SPF record.
func ParseSPF(s string) (*SPFRecord, error) {
	record := &SPFRecord{}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, errors.New("empty record")
	}
	if strings.ToLower(fields[0]) != "v=spf1" {
		return nil, errors.New("record doesn't begin with v=spf1")
	}

	for i, field := range fields {
		if i == 0 {
			continue
		}
		matches := modifierRe.FindStringSubmatch(field)
		if matches != nil {
			switch strings.ToLower(matches[1]) {
			case "redirect":
				if record.Redirect != "" {
					return nil, errors.New("multiple redirect modifiers")
				}
				if !validDomainSpec(matches[2]) {
					return nil, errors.New("invalid domain-spec in redirect")
				}
				record.Redirect = matches[2]
			case "exp":
				if record.Exp != "" {
					return nil, errors.New("multiple exp modifiers")
				}
				if !validDomainSpec(matches[2]) {
					return nil, errors.New("invalid domain-spec in exp")
				}
				record.Exp = matches[2]
			default:
				if !MacroIsValid(matches[2]) {
					return nil, errors.New("invalid macro-string in modifier")
				}
				record.OtherModifiers = append(record.OtherModifiers, field)
			}
			continue
		}
		m, err := NewMechanism(field)
		if err != nil {
			return nil, fmt.Errorf("In field '%s': %w", field, err)
		}
		record.Mechanisms = append(record.Mechanisms, m)
	}

	return record, nil
}
