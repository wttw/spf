package spf

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestDefaultResolverRetriesTruncatedUDPOverTCP(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		switch w.RemoteAddr().Network() {
		case "udp":
			m.Truncated = true
		case "tcp":
			m.Answer = []dns.RR{
					&dns.TXT{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    30,
					},
					Txt: []string{"v=spf1 -all"},
				},
			}
		default:
			t.Fatalf("unexpected network %q", w.RemoteAddr().Network())
		}

		if err := w.WriteMsg(m); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpLn, Handler: handler}

	go func() {
		_ = udpServer.ActivateAndServe()
	}()
	go func() {
		_ = tcpServer.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})

	res := &DefaultResolver{
		client:  &dns.Client{Net: "udp"},
		servers: []string{tcpLn.Addr().String()},
	}

	r := &dns.Msg{}
	r.SetQuestion("example.com.", dns.TypeTXT)

	m, err := res.Resolve(context.Background(), r)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if m.Truncated {
		t.Fatal("Resolve() returned a truncated reply")
	}
	if len(m.Answer) != 1 {
		t.Fatalf("Resolve() returned %d answers, want 1", len(m.Answer))
	}
	txt, ok := m.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("Resolve() answer type = %T, want *dns.TXT", m.Answer[0])
	}
	if got := txt.Txt[0]; got != "v=spf1 -all" {
		t.Fatalf("Resolve() TXT = %q, want %q", got, "v=spf1 -all")
	}
}
