package spf

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

// 5.5.  "ptr" (do not use) (RFC 7208)
//
//   This mechanism tests whether the DNS reverse-mapping for <ip> exists
//   and correctly points to a domain name within a particular domain.
//   This mechanism SHOULD NOT be published.  See the note at the end of
//   this section for more information.
//
//   ptr              = "ptr"    [ ":" domain-spec ]
//
//   The <ip>'s name is looked up using this procedure:
//
//   o  Perform a DNS reverse-mapping for <ip>: Look up the corresponding
//      PTR record in "in-addr.arpa." if the address is an IPv4 address
//      and in "ip6.arpa." if it is an IPv6 address.
//
//   o  For each record returned, validate the domain name by looking up
//      its IP addresses.  To prevent DoS attacks, the PTR processing
//      limits defined in Section 4.6.4 MUST be applied.  If they are
//      exceeded, processing is terminated and the mechanism does not
//      match.
//
//   o  If <ip> is among the returned IP addresses, then that domain name
//      is validated.
//
//   Check all validated domain names to see if they either match the
//   <target-name> domain or are a subdomain of the <target-name> domain.
//   If any do, this mechanism matches.  If no validated domain name can
//   be found, or if none of the validated domain names match or are a
//   subdomain of the <target-name>, this mechanism fails to match.  If a
//   DNS error occurs while doing the PTR RR lookup, then this mechanism
//   fails to match.  If a DNS error occurs while doing an A RR lookup,
//   then that domain name is skipped and the search continues.
//
//   This mechanism matches if
//
//   o  the <target-name> is a subdomain of a validated domain name, or
//
//   o  the <target-name> and a validated domain name are the same.
//
//   For example, "mail.example.com" is within the domain "example.com",
//   but "mail.bad-example.com" is not.

// MechanismPTR represents the SPF "ptr" mechanism.
func (m MechanismPTR) Evaluate(ctx context.Context, result *Result, domain string) (ResultType, error) {
	c := result.c
	var qtype uint16
	if result.ip.To4() != nil {
		qtype = dns.TypeA
	} else {
		qtype = dns.TypeAAAA
	}

	target, err := result.c.ExpandDomainSpec(ctx, m.DomainSpec, result, domain, false)
	if err != nil {
		return Permerror, err
	}
	target = dns.Fqdn(target)
	if !validDomainName(target) {
		return Fail, fmt.Errorf("invalid hostname '%s'", target)
	}

	rev, err := dns.ReverseAddr(result.ip.String())
	if err != nil {
		return Permerror, err
	}
	rrs, resultType, err := c.lookupDNS(ctx, rev, dns.TypePTR, result)
	if err != nil {
		return resultType, err
	}

	//    When evaluating the "ptr" mechanism or the %{p} macro, the number of
	//   "PTR" resource records queried is included in the overall limit of 10
	//   mechanisms/modifiers that cause DNS lookups as described above.  In
	//   addition to that limit, the evaluation of each "PTR" record MUST NOT
	//   result in querying more than 10 address records -- either "A" or
	//   "AAAA" resource records.  If this limit is exceeded, all records
	//   other than the first 10 MUST be ignored.

	if len(rrs) > c.PtrAddressLimit {
		rrs = rrs[:c.PtrAddressLimit]
	}

	for _, rr := range rrs {
		hostname := rr.(*dns.PTR).Ptr
		// If it's never going to match, skip the A/AAAA lookups
		if !dns.IsSubDomain(target, hostname) {
			continue
		}

		addresses, _, err := c.lookupAddresses(ctx, hostname, qtype, result)
		if err != nil {
			continue
		}

		for _, address := range addresses {
			if address.Equal(result.ip) {
				// this hostname is validated and matches
				return m.Qualifier, nil
			}
		}
	}
	return None, nil
}

func expandPtrMacro(ctx context.Context, result *Result, target string) string {
	c := result.c
	var qtype uint16
	if result.ip.To4() != nil {
		qtype = dns.TypeA
	} else {
		qtype = dns.TypeAAAA
	}
	rev, err := dns.ReverseAddr(result.ip.String())
	if err != nil {
		return "unknown"
	}
	rrs, _, err := c.lookupDNS(ctx, rev, dns.TypePTR, result)
	if err != nil {
		return "unknown"
	}
	if len(rrs) > c.PtrAddressLimit {
		rrs = rrs[:c.PtrAddressLimit]
	}

	possibles := []string{}
	target = dns.Fqdn(target)
	for _, rr := range rrs {
		hostname := rr.(*dns.PTR).Ptr
		addresses, _, err := c.lookupAddresses(ctx, hostname, qtype, result)
		if err != nil {
			continue
		}

		for _, address := range addresses {
			if address.Equal(result.ip) {
				// this hostname is validated and matches
				if strings.ToLower(hostname) == strings.ToLower(target) {
					return strings.TrimSuffix(hostname, ".")
				}
				possibles = append(possibles, hostname)
				break;
			}
		}
	}
	for _, possible := range possibles {
		if dns.IsSubDomain(target, possible) {
			return  strings.TrimSuffix(possible, ".")
		}
	}
	if len(possibles) > 0 {
		return strings.TrimSuffix(possibles[0], ".")
	}
	return "unknown"
}
