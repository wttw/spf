package spf

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
)

// ResolvConf holds the path to a resolv.conf(5) format file used to
// configure DefaultResolver.
var ResolvConf = "/etc/resolv.conf"

// Resolver is used for all DNS lookups during an SPF check
type Resolver interface {
	Resolve(ctx context.Context, r *dns.Msg) (*dns.Msg, error)
}

var _ Resolver = &DefaultResolver{}

// DefaultResolver is the Resolver that will be used in default constructed Checkers.
type DefaultResolver struct {
	client  *dns.Client
	servers []string
}

// Resolve performs a low level DNS lookup using miekg/dns format packet representation.
func (res *DefaultResolver) Resolve(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	if res.client == nil {
		clientConfig, err := dnsconf.FromFile(ResolvConf)
		if err != nil {
			return nil, fmt.Errorf("Failed to load %s: %w", ResolvConf, err)
		}
		if len(clientConfig.Servers) == 0 {
			return nil, fmt.Errorf("No nameservers configured in %s", ResolvConf)
		}
		res.servers = make([]string, len(clientConfig.Servers))
		for i, server := range clientConfig.Servers {
			res.servers[i] = fmt.Sprintf("%s:%s", server, clientConfig.Port)
		}
		res.client = new(dns.Client)
	}
	r.UDPSize, r.Security = 4096, true
	var m *dns.Msg
	var err error
	for _, server := range res.servers {
		m, _, err = res.client.Exchange(ctx, r, "udp", server)
		if err == nil {
			return m, nil
		}
	}
	return m, err
}
