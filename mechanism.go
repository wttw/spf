package spf

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Mechanism holds an SPF mechanism
type Mechanism interface {
	Evaluate(ctx context.Context, result *Result, domain string) (ResultType, error)
	String() string
}

var _ Mechanism = MechanismAll{}
var _ Mechanism = MechanismInclude{}
var _ Mechanism = MechanismA{}
var _ Mechanism = MechanismMX{}
var _ Mechanism = MechanismIp4{}
var _ Mechanism = MechanismIp6{}
var _ Mechanism = MechanismExists{}
var _ Mechanism = MechanismPTR{}

// 5.1.  "all"
//
//   all              = "all"
//
//   The "all" mechanism is a test that always matches.  It is used as the
//   rightmost mechanism in a record to provide an explicit default.

// MechanismAll represents an SPF "all" mechanism, it always matches.
type MechanismAll struct {
	Qualifier ResultType
}

func (m MechanismAll) Evaluate(_ context.Context, _ *Result, _ string) (ResultType, error) {
	return m.Qualifier, nil
}

func (m MechanismAll) String() string {
	return mechanismString(m.Qualifier, "all","", net.IPMask{}, net.IPMask{})
}

// 5.2.  "include"
//
//   include          = "include"  ":" domain-spec
//
//   The "include" mechanism triggers a recursive evaluation of
//   check_host().
//
//   1.  The <domain-spec> is expanded as per Section 7.
//
//   2.  check_host() is evaluated with the resulting string as the
//       <domain>.  The <ip> and <sender> arguments remain the same as in
//       the current evaluation of check_host().
//
//   3.  The recursive evaluation returns match, not-match, or an error.
//
//   4.  If it returns match, then the appropriate result for the
//       "include" mechanism is used (e.g., include or +include produces a
//       "pass" result and -include produces "fail").
//
//   5.  If it returns not-match or an error, the parent check_host()
//       resumes processing as per the table below, with the previous
//       value of <domain> restored.

// MechanismInclude represents an SPF "include" mechanism, it matches based
// on the result of an SPF check on another host name.
type MechanismInclude struct {
	Qualifier  ResultType
	DomainSpec string
}

func (m MechanismInclude) Evaluate(ctx context.Context, result *Result, domain string) (ResultType, error) {
	dom, err := result.c.ExpandDomainSpec(ctx, m.DomainSpec, result, domain, false)

	if err != nil {
		return Permerror, err
	}

	if !validDomainName(dom) {
		return None, fmt.Errorf("invalid hostname '%s'", dom)
	}
	includeResult := result.c.checkHost(ctx, result, dns.Fqdn(dom), true, false)

	switch includeResult {
	case Pass:
		return m.Qualifier, nil
	case Fail, Softfail, Neutral:
		return None, nil
	case Temperror:
		return Temperror, nil
	case Permerror, None:
		return Permerror, nil
	}
	return Permerror, errors.New("unhandled case in MechanismInclude")
}

func (m MechanismInclude) String() string {
	return mechanismString(m.Qualifier, "include",m.DomainSpec, net.IPMask{}, net.IPMask{})
}

// 5.3.  "a"
//
//   This mechanism matches if <ip> is one of the <target-name>'s IP
//   addresses.  For clarity, this means the "a" mechanism also matches
//   AAAA records.
//
//   a                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
//
//   An address lookup is done on the <target-name> using the type of
//   lookup (A or AAAA) appropriate for the connection type (IPv4 or
//   IPv6).  The <ip> is compared to the returned address(es).  If any
//   address matches, the mechanism matches.

// MechanismA represents an SPF "a" mechanism. It matches based on DNS lookups
// of A and AAAA records for it's domain-spec.
type MechanismA struct {
	Qualifier  ResultType
	DomainSpec string
	Mask4      net.IPMask
	Mask6      net.IPMask
}

func (m MechanismA) Evaluate(ctx context.Context, result *Result, domain string) (ResultType, error) {
	result.DNSQueries++
	var qtype uint16
	if result.ip.To4() == nil {
		qtype = dns.TypeAAAA
	} else {
		qtype = dns.TypeA
	}

	target, err := result.c.ExpandDomainSpec(ctx, m.DomainSpec, result, domain, false)
	if err != nil {
		return Permerror, err
	}
	if !validDomainName(target) {
		return None, fmt.Errorf("invalid hostname '%s'", target)
	}

	rrs, resultType, err := result.c.lookupDNS(ctx, target, qtype, result)
	if resultType != None {
		return resultType, err
	}

	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if (&net.IPNet{IP: v.A, Mask: m.Mask4}).Contains(result.ip) {
				return m.Qualifier, nil
			}
		case *dns.AAAA:
			if (&net.IPNet{IP: v.AAAA, Mask: m.Mask6}).Contains(result.ip) {
				return m.Qualifier, nil
			}
		}
	}
	return None, nil
}

func (m MechanismA) String() string {
	return mechanismString(m.Qualifier, "a", m.DomainSpec, m.Mask4, m.Mask6)
}

// 5.4.  "mx"
//
//   This mechanism matches if <ip> is one of the MX hosts for a domain
//   name.
//
//   mx               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
//
//   check_host() first performs an MX lookup on the <target-name>.  Then
//   it performs an address lookup on each MX name returned.  The <ip> is
//   compared to each returned IP address.  To prevent denial-of-service
//   (DoS) attacks, the processing limits defined in Section 4.6.4 MUST be
//   followed.  If the MX lookup limit is exceeded, then "permerror" is
//   returned and the evaluation is terminated.  If any address matches,
//   the mechanism matches.

// MechanismMX represents an SPF "mx" mechanism. It matches based on DNS lookups
// of MX records for it's domain-spec, and DNS lookups for A and AAAA records
// for the results of those.
type MechanismMX struct {
	Qualifier  ResultType
	DomainSpec string
	Mask4      net.IPMask
	Mask6      net.IPMask
}


func (m MechanismMX) Evaluate(ctx context.Context, result *Result, domain string) (ResultType, error) {
	result.DNSQueries++
	var qtype uint16
	var mask net.IPMask
	if result.ip.To4() == nil {
		qtype = dns.TypeAAAA
		mask = m.Mask6
	} else {
		qtype = dns.TypeA
		mask = m.Mask4
	}

	target, err := result.c.ExpandDomainSpec(ctx, m.DomainSpec, result, domain, false)
	if err != nil {
		return Permerror, err
	}
	if !validDomainName(target) {
		return None, fmt.Errorf("invalid hostname '%s'", target)
	}

	mxrrs, resultType, err := result.c.lookupDNS(ctx, target, dns.TypeMX, result)
	if resultType != None {
		return resultType, err
	}

	mxcount := 0
	for _, mxrr := range mxrrs {
		mx := mxrr.(*dns.MX)
		mxcount++
		if mxcount > result.c.MXAddressLimit {
			return Permerror, fmt.Errorf("limit of %d MX results exceeded for %s", result.c.MXAddressLimit, target)
		}
		addresses, resultType, err := result.c.lookupAddresses(ctx, mx.Mx, qtype, result)
		if resultType != None {
			return resultType, err
		}

		for _, address := range addresses {
			if (&net.IPNet{IP: address, Mask: mask}).Contains(result.ip) {
				return m.Qualifier, nil
			}
		}
	}

	return None, nil
}

func (m MechanismMX) String() string {
	return mechanismString(m.Qualifier, "mx", m.DomainSpec, m.Mask4, m.Mask6)
}

// 5.5.  "ptr" (do not use)

// MechanismPTR represents an SPF "ptr" mechanism.
type MechanismPTR struct {
	Qualifier  ResultType
	DomainSpec string
}

func (m MechanismPTR) String() string {
	return mechanismString(m.Qualifier, "ptr", m.DomainSpec, net.IPMask{}, net.IPMask{})
}

// MechanismPtr.Evaluate is in ptr.go


// 5.6.  "ip4" and "ip6"
//
//   These mechanisms test whether <ip> is contained within a given
//   IP network.
//
//   ip4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
//   ip6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]

// MechanismIp4 represents an SPF "ip4" mechanism. It matches based on the
// connecting IP being within the provided address range.
type MechanismIp4 struct {
	Qualifier ResultType
	Net       *net.IPNet
}

func (m MechanismIp4) Evaluate(_ context.Context, result *Result, _ string) (ResultType, error) {
	if m.Net.Contains(result.ip) {
		return m.Qualifier, nil
	}
	return None, nil
}

func (m MechanismIp4) String() string {
	return mechanismString(m.Qualifier, "ip4", m.Net.String(), net.IPMask{}, net.IPMask{})
}

// MechanismIp6 represents an SPF "ip6" mechanism. It matches based on the
// connecting IP being within the provided address range.
type MechanismIp6 struct {
	Qualifier ResultType
	Net       *net.IPNet
}

func (m MechanismIp6) Evaluate(_ context.Context, result *Result, _ string) (ResultType, error) {
	if m.Net.Contains(result.ip) {
		return m.Qualifier, nil
	}
	return None, nil
}

func (m MechanismIp6) String() string {
	return mechanismString(m.Qualifier, "ip6", m.Net.String(), net.IPMask{}, net.IPMask{})
}

// 5.7.  "exists"
//
//   This mechanism is used to construct an arbitrary domain name that is
//   used for a DNS A record query.  It allows for complicated schemes
//   involving arbitrary parts of the mail envelope to determine what is
//   permitted.
//
//   exists           = "exists"   ":" domain-spec
//
//   The <domain-spec> is expanded as per Section 7.  The resulting domain
//   name is used for a DNS A RR lookup (even when the connection type is
//   IPv6).  If any A record is returned, this mechanism matches.

// MechanismExists represents an SPF "exists" mechanism. It matches based on
// the existence of a DNS A record for the - macro-expanded - domain-spec.
type MechanismExists struct {
	Qualifier  ResultType
	DomainSpec string
}

func (m MechanismExists) Evaluate(ctx context.Context, result *Result, domain string) (ResultType, error) {
	result.DNSQueries++
	target, err := result.c.ExpandDomainSpec(ctx, m.DomainSpec, result, domain, false)
	if err != nil {
		return Permerror, err
	}
	if !validDomainName(target) {
		return None, fmt.Errorf("invalid hostname '%s'", target)
	}
	arecs, resultType, err := result.c.lookupAddresses(ctx, target, dns.TypeA, result)
	if resultType != None {
		return resultType, err
	}
	if len(arecs) == 0 {
		return None, nil
	}
	return m.Qualifier, nil
}

func (m MechanismExists) String() string {
	return mechanismString(m.Qualifier, "exists", m.DomainSpec, net.IPMask{}, net.IPMask{})
}


//   ip4-cidr-length  = "/" ("0" / %x31-39 0*1DIGIT) ; value range 0-32
//   ip6-cidr-length  = "/" ("0" / %x31-39 0*2DIGIT) ; value range 0-128
//   dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]

var v4CIDRRe = regexp.MustCompile(`/[0-9]{1,2}$`)
var v6CIDRRe = regexp.MustCompile(`//[0-9]{1,3}$`)

func dualCIDR(s string) (string, net.IPMask, net.IPMask, error) {
	loc6 := v6CIDRRe.FindStringIndex(s)

	var err error
	var v6len = 128
	if loc6 != nil {
		v6len, err = strconv.Atoi(s[loc6[0]+2:])
		if err != nil || v6len > 128 {
			return "", nil, nil, fmt.Errorf("invalid ipv6 cidr range in dual-cidr: %s", s[loc6[0]:])
		}
		s = s[:loc6[0]]
	}

	loc4 := v4CIDRRe.FindStringIndex(s)
	var v4len = 32
	if loc4 != nil {
		v4len, err = strconv.Atoi(s[loc4[0]+1:])

		if err != nil || v4len > 32 {
			return "", nil, nil, fmt.Errorf("invalid ipv4 cidr range in dual-cidr: %s", s[loc4[0]:])
		}
		s = s[:loc4[0]]
	}

	return s, net.CIDRMask(v4len, 32), net.CIDRMask(v6len, 128), nil
}

// NewMechanism creates a new Mechanism from it's text representation
func NewMechanism(raw string) (Mechanism, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty mechanism")
	}

	//matches := modifierRe.FindStringSubmatch(raw)
	//if len(matches) != 0 {
	//	m.IsModifier = true
	//	m.Type = strings.ToLower(matches[1])
	//	m.Parameter = matches[2]
	//	return nil, nil
	//}

	// 4.6.2.  Mechanisms (RFC 7208)
	//    The possible qualifiers, and the results they cause check_host() to
	//   return, are as follows:
	//
	//      "+" pass
	//      "-" fail
	//      "~" softfail
	//      "?" neutral
	//
	//   The qualifier is optional and defaults to "+".

	var qualifier ResultType
	switch raw[0] {
	case '+':
		qualifier = Pass
		raw = raw[1:]
	case '-':
		qualifier = Fail
		raw = raw[1:]
	case '~':
		qualifier = Softfail
		raw = raw[1:]
	case '?':
		qualifier = Neutral
		raw = raw[1:]
	default:
		qualifier = Pass
	}

	var mtype, parameter string
	emptyParam := false

	separator := strings.IndexAny(raw, ":/")
	if separator == -1 {
		mtype = strings.ToLower(raw)
	} else {
		mtype = strings.ToLower(raw[:separator])
		parameter = raw[separator:]
		if parameter[0] == ':' {
			parameter = parameter[1:]
			emptyParam = len(parameter) == 0
		}
	}

	switch mtype {
	case "all":
		if parameter != "" {
			return nil, errors.New("all doesn't take parameters")
		}
		return MechanismAll{Qualifier: qualifier}, nil
	case "include":
		if parameter == "" {
			return nil, errors.New("include requires a domain spec")
		}
		if !validDomainSpec(parameter) {
			return nil, errors.New("invalid domain-spec")
		}
		return MechanismInclude{
			Qualifier:  qualifier,
			DomainSpec: parameter,
		}, nil
	case "a":
		if emptyParam {
			return nil, errors.New("empty domain in a mechanism")
		}
		domainSpec, v4Mask, v6Mask, err := dualCIDR(parameter)
		if err != nil {
			return nil, err
		}
		if !validOptionalDomainSpec(domainSpec) {
			return nil, errors.New("invalid domain-spec")
		}
		return MechanismA{
			Qualifier:  qualifier,
			DomainSpec: domainSpec,
			Mask4:      v4Mask,
			Mask6:      v6Mask,
		}, nil
	case "mx":
		if emptyParam {
			return nil, errors.New("empty domain in mx mechanism")
		}
		domainSpec, v4Mask, v6Mask, err := dualCIDR(parameter)
		if err != nil {
			return nil, err
		}
		if !validOptionalDomainSpec(domainSpec) {
			return nil, errors.New("invalid domain-spec")
		}
		return MechanismMX{
			Qualifier:  qualifier,
			DomainSpec: domainSpec,
			Mask4:      v4Mask,
			Mask6:      v6Mask,
		}, nil
	case "ptr":
		if emptyParam {
			return nil, errors.New("empty domain in ptr mechanism")
		}
		if !validOptionalDomainSpec(parameter) {
			return nil, errors.New("invalid domain-spec")
		}
		return MechanismPTR{
			Qualifier:  qualifier,
			DomainSpec: parameter,
		}, nil
	case "ip4":
		addr := parameter
		if !strings.Contains(addr, "/") {
			addr = addr + "/32"
		}
		ip, cidr, err := parseCIDR(addr)
		if err != nil {
			return nil, errors.New("invalid address format")
		}
		if ip.To4() == nil {
			return nil, errors.New("non-IP4 address in ip4")
		}
		return MechanismIp4{
			Qualifier: qualifier,
			Net:       cidr,
		}, nil
	case "ip6":
		addr := parameter
		if !strings.Contains(addr, "/") {
			addr = addr + "/128"
		}
		ip, cidr, err := parseCIDR(addr)
		if err != nil {
			return nil, errors.New("invalid address format")
		}
		if len(ip) != 16 {
			return nil, errors.New("non-IP6 address in ip6:")
		}
		return MechanismIp6{
			Qualifier: qualifier,
			Net:       cidr,
		}, nil
	case "exists":
		if parameter == "" {
			return nil, errors.New("exists requires a domain spec")
		}
		if !validDomainSpec(parameter) {
			return nil, errors.New("invalid domain-spec")
		}
		return MechanismExists{
			Qualifier:  qualifier,
			DomainSpec: parameter,
		}, nil
	default:
		return nil, fmt.Errorf("unrecognized mechanism '%s'", mtype)
	}
}

// Stringer helpers

// ResultChar maps between the spf.ResultType and the equivalent single character
// qualifier used in SPF text format.
var ResultChar=map[ResultType]string{
	None: "",
	Neutral: "?",
	Pass: "",
	Fail: "-",
	Softfail: "~",
}

func mechanismString(qualifier ResultType, name string, parameter string, mask4, mask6 net.IPMask) string {
	var sb strings.Builder
	mod, ok := ResultChar[qualifier]
	if ok {
		sb.WriteString(mod)
	}
	sb.WriteString(name)
	if parameter != "" {
		sb.WriteString(":")
		sb.WriteString(parameter)
	}

	ones, bits := mask4.Size()
	if bits != 0 && ones !=32{
		sb.WriteString("/")
		sb.WriteString(strconv.Itoa(ones))
	}
	ones, bits = mask6.Size()
	if bits != 0 && ones != 128 {
		sb.WriteString("//")
		sb.WriteString(strconv.Itoa(ones))
	}
	return sb.String()
}
