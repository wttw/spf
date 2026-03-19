package spf_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/wttw/spf/v2"

	"gopkg.in/yaml.v2"
)

type Test struct {
	Spec        interface{}
	Description string
	Helo        string
	Host        netip.Addr
	MailFrom    string
	Result      interface{}
	Explanation string
}

type Answer interface{}

type Suite struct {
	Description string `yaml:"description"`
	Tests       map[string]Test
	ZoneData    map[string][]Answer
}

func (e Test) ResultMatches(s string) bool {
	acceptable := toSlice(e.Result)
	for _, a := range acceptable {
		if s == a {
			return true
		}
	}
	return false
}

func toSlice(i interface{}) []string {
	switch v := i.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		ret := make([]string, len(v))
		for j, k := range v {
			ret[j] = k.(string)
		}
		return ret
	default:
		panic(fmt.Errorf("unexpected type in RR: %T, %#v", i, i))
	}
}

type TestResolver map[string]map[uint16]*dns.Msg

var _ spf.Resolver = TestResolver{}

func (res TestResolver) Resolve(_ context.Context, r *dns.Msg) (*dns.Msg, error) {
	m := &dns.Msg{}
	dnsutil.SetReply(m, r)

	hostRRs, ok := res[strings.ToLower(r.Question[0].Header().Name)]
	if !ok {
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		fmt.Printf("NXDOMAIN Question: %v\n", r.Question[0].String())
		return m, nil
	}

	response, ok := hostRRs[dns.RRToType(r.Question[0])]
	if ok {
		m = response.Copy()
		//dnsutil.SetReply(m, r)
	} else {

		_, ok = hostRRs[0]
		if ok {
			m.Rcode = dns.RcodeServerFailure // SERVFAIL
			fmt.Printf("SERVFAIL Question: %v\n", r.Question[0].String())
			return m, nil
		}
	}

	m.Rcode = dns.RcodeSuccess
	fmt.Printf("SUCCESS Question: %v -> %v\n", r.Question[0].String(), m.Answer)
	return m, nil
}

func (s Suite) Zone(t *testing.T) TestResolver {
	ret := TestResolver{}

	// Our test vectors have a weird mix of RRs in their sample DNS data
	// In some tests there are both SPF and TXT records, which should be used as-is
	// In others there's just SPF, which should all be treated as TXT (or duplicated
	// as TXT?)

	for hostname, answers := range s.ZoneData {
		hostname = strings.ToLower(dnsutil.Fqdn(hostname))
		_, ok := ret[hostname]
		if !ok {
			ret[hostname] = map[uint16]*dns.Msg{}
		}

		seenTXT := false
		for _, answer := range answers {
			switch v := answer.(type) {
			case map[interface{}]interface{}:
				for typeThing := range v {
					typeString, ok := typeThing.(string)
					if ok && typeString == "TXT" /* && strings.HasPrefix(value.(string), "v=spf1")*/ {
						seenTXT = true
					}
				}
			}
		}

		for _, answer := range answers {
			switch v := answer.(type) {
			case string:
				if v != "TIMEOUT" {
					t.Fatalf("Unrecognized value '%s' in %s", v, hostname)
				}
				ret[hostname][0] = nil
			case map[interface{}]interface{}:
				for typeThing, value := range v {
					typeString, ok := typeThing.(string)
					if !ok {
						t.Fatalf("Unrecognized RR key %T in %s", typeThing, hostname)
					}
					typeID, ok := dns.StringToType[typeString]
					if !ok {
						t.Fatalf("Unrecognized RR type '%s' in %s", typeString, hostname)
					}

					var rr dns.RR
					hdr := dns.Header{
						Name:  hostname,
						Class: dns.ClassINET,
						TTL:   30,
					}
					switch typeID {
					case dns.TypeSPF:
						rr = &dns.SPF{
							TXT: dns.TXT{
								Hdr: hdr,
								TXT: rdata.TXT{
									Txt: toSlice(value),
								},
							},
						}
					case dns.TypeMX:
						slice := value.([]interface{})
						weight := slice[0].(int)
						rr = &dns.MX{
							Hdr: hdr,
							MX: rdata.MX{
								Preference: uint16(weight),
								Mx:         dnsutil.Fqdn(slice[1].(string)),
							},
						}
					case dns.TypeTXT:
						rr = &dns.TXT{
							Hdr: hdr,
							TXT: rdata.TXT{
								Txt: toSlice(value),
							},
						}
					case dns.TypeA:
						rr = &dns.A{
							Hdr: hdr,
							A: rdata.A{
								Addr: netip.MustParseAddr(value.(string)),
							},
						}
					case dns.TypeAAAA:
						rr = &dns.AAAA{
							Hdr: hdr,
							AAAA: rdata.AAAA{
								Addr: netip.MustParseAddr(value.(string)),
							},
						}
					case dns.TypePTR:
						rr = &dns.PTR{
							Hdr: hdr,
							PTR: rdata.PTR{
								Ptr: dnsutil.Fqdn(value.(string)),
							},
						}
					case dns.TypeCNAME:
						rr = &dns.CNAME{
							Hdr: hdr,
							CNAME: rdata.CNAME{
								Target: value.(string),
							},
						}
					default:
						t.Fatalf("Unhandled RR type '%s' in %s", typeString, hostname)
					}

					if typeID == dns.TypeTXT && rr.(*dns.TXT).Txt[0] == "NONE" {
						continue
					}

					m, ok := ret[hostname][typeID]
					if !ok {
						m = &dns.Msg{}
					}
					m.Answer = append(m.Answer, rr)
					ret[hostname][typeID] = m

					// Dupe the SPF record to TXT
					if !seenTXT && typeID == dns.TypeSPF {
						m, ok := ret[hostname][dns.TypeTXT]
						if !ok {
							m = &dns.Msg{}
						}
						m.Answer = append(m.Answer, &dns.TXT{
							Hdr: dns.Header{
								Name:  hostname,
								Class: dns.ClassINET,
								TTL:   30,
							},
							TXT: rdata.TXT{
								Txt: toSlice(value),
							},
						})
						ret[hostname][dns.TypeTXT] = m
					}
				}
			default:
				t.Fatalf("Unexpected RR type %T, %#v  in %s", answer, answer, hostname)
			}
		}
	}
	return ret
}

func loadSuites(t *testing.T, filename string) []Suite {
	suites := []Suite{}
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("failed to open %s: %v", filename, err)
	}
	decoder := yaml.NewDecoder(f)
	for {
		var s Suite
		err = decoder.Decode(&s)
		if err != nil {
			if err == io.EOF {
				return suites
			}
			t.Fatalf("while reading %s: %v", filename, err)
		}
		suites = append(suites, s)
	}
}

func runSuite(s Suite) func(*testing.T) {
	return func(t *testing.T) {
		resolver := s.Zone(t)
		checker := spf.NewChecker()
		checker.Resolver = resolver
		for name, test := range s.Tests {
			t.Run(name, func(t *testing.T) {
				actual := checker.SPF(context.Background(), test.Host, test.MailFrom, test.Helo)
				if !test.ResultMatches(actual.String()) {
					t.Errorf("expected %v, actual %s", test.Result, actual.String())
				}
			})
		}
	}
}

func TestSPF(t *testing.T) {
	for _, filename := range []string{
		"testdata/openspf/pyspf-tests.yml",
		"testdata/openspf/rfc7208-tests.yml",
	} {
		for _, s := range loadSuites(t, filename) {
			t.Run(filepath.Base(filename)+"/"+s.Description, runSuite(s))
		}
	}
}
