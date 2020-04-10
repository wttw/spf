package spf

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var spfPrefixRe = regexp.MustCompile(`(?i)^v=spf1(?: |$)`)

// Gets a single SPF record for a domain, as a single string
func (c *Checker) getSPFRecord(ctx context.Context, domain string) (string, ResultType, error) {
	r := &dns.Msg{}
	r.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	m, err := c.resolve(ctx, r)
	if err != nil {
		return "", Temperror, err
	}
	// 4.4. Record Lookup (RFC 7208)
	//  If the DNS lookup returns a server failure (RCODE 2) or some other
	//  error (RCODE other than 0 or 3), or if the lookup times out, then
	//  check_host() terminates immediately with the result "temperror".
	switch m.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return "", Temperror, nil
	}

	// 4.5.  Selecting Records (RFC 7208)
	//
	//  Records begin with a version section:
	//
	//  record           = version terms *SP
	//  version          = "v=spf1"
	//
	//  Starting with the set of records that were returned by the lookup,
	//  discard records that do not begin with a version section of exactly
	//  "v=spf1".  Note that the version section is terminated by either an
	//  SP character or the end of the record.  As an example, a record with
	//  a version section of "v=spf10" does not match and is discarded.

	spfRecords := make([]string, 0, 1)
	for _, rr := range m.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		record := strings.Join(txt.Txt, "")
		if spfPrefixRe.MatchString(record) {
			spfRecords = append(spfRecords, record)
		}
	}

	// 4.5. Selecting Records (RFC 7208)
	//
	//  If the resultant record set includes no records, check_host()
	//  produces the "none" result.  If the resultant record set includes
	//  more than one record, check_host() produces the "permerror" result.

	switch len(spfRecords) {
	case 0:
		return "", None, nil
	case 1:
		return spfRecords[0], None, nil
	default:
		return "", Permerror, nil
	}
}

var validDomainSuffix = regexp.MustCompile(`(?i)\.([a-z0-9][a-z0-9-]*[a-z0-9])\.?$`)
var allNumeric = regexp.MustCompile(`^[0-9]*$`)

// DNS allows arbitrary 8 bit data, so a simple dns.IsDomainName() isn't strict enough
func validDomainName(hostname string) bool {
	atoms, ok := dns.IsDomainName(hostname)
	if !ok || atoms < 2 {
		return false
	}
	//if domainInvalidChars.MatchString(hostname) {
	//	return false
	//}

	matches := validDomainSuffix.FindStringSubmatch(hostname)
	if matches == nil {
		return false
	}
	if allNumeric.MatchString(matches[1]) {
		return false
	}
	return true
}

func validOptionalDomainSpec(domainSpec string) bool {
	return domainSpec == "" || validDomainSpec(domainSpec)
}

// 7.1.  Formal Specification
//
//   The ABNF description for a macro is as follows:
//
//   domain-spec      = macro-string domain-end
//   domain-end       = ( "." toplabel [ "." ] ) / macro-expand
//
//   toplabel         = ( *alphanum ALPHA *alphanum ) /
//                      ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
//   alphanum         = ALPHA / DIGIT
//

// .. so the domainSpec must end in either a macro token or a TLD

func validDomainSpec(domainSpec string) bool {
	if validDomainName(domainSpec) {
		return true
	}
	if !MacroIsValid(domainSpec) {
		return false
	}
	if strings.HasSuffix(domainSpec, "}") {
		return true
	}
	matches := validDomainSuffix.FindStringSubmatch(domainSpec)
	if matches == nil {
		return false
	}
	if allNumeric.MatchString(matches[1]) {
		return false
	}
	return true
}

// lookupDNS does a basic DNS query, returning only matching records, and deals
// with void query lookups
func (c *Checker) lookupDNS(ctx context.Context, hostname string, qtype uint16, result *Result) ([]dns.RR, ResultType, error) {
	r := &dns.Msg{}
	r.SetQuestion(dns.Fqdn(hostname), qtype)
	m, err := c.resolve(ctx, r)
	if err != nil {
		return []dns.RR{}, Temperror, err
	}

	if m.Rcode == dns.RcodeNameError || (m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0) {
		// NXDOMAIN or zero records
		result.VoidLookups++
		if result.VoidLookups > c.VoidQueryLimit {
			return []dns.RR{}, Permerror, fmt.Errorf("void queries exceeded limit of %d", c.VoidQueryLimit)
		}
		return []dns.RR{}, None, nil
	}

	if m.Rcode != dns.RcodeSuccess {
		return []dns.RR{}, Temperror, nil
	}

	ret := make([]dns.RR, 0, len(m.Answer))
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype {
			ret = append(ret, rr)
		}
	}
	return ret, None, nil
}

// lookupAddresses does either an A or AAAA lookup, returning matching results as []net.IP
func (c *Checker) lookupAddresses(ctx context.Context, target string, qtype uint16, result *Result) ([]net.IP, ResultType, error) {
	ret := []net.IP{}
	rrs, resultType, err := c.lookupDNS(ctx, target, qtype, result)
	if resultType != None {
		return []net.IP{}, resultType, err
	}
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			ret = append(ret, v.A)
		case *dns.AAAA:
			ret = append(ret, v.AAAA)
		}
	}
	return ret, None, nil
}

// like net.ParseCIDR but a little less forgiving
func parseCIDR(s string) (net.IP, *net.IPNet, error) {
	ip, mask, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil, err
	}
	i := strings.Index(s, "/")
	if i < 0 {
		return nil, nil, &net.ParseError{Type: "CIDR address", Text: s}
	}

	maskIn := s[i+1:]
	ones, _ := mask.Mask.Size()
	if maskIn != strconv.Itoa(ones) {
		return nil, nil, &net.ParseError{Type: "CIDR address", Text: s}
	}
	return ip, mask, err
}
