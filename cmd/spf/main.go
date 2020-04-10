/*
spf is a commandline tool for evaluating spf records.

 spf -ip 8.8.8.8 -from steve@aol.com

 Result: softfail
 Error:  <nil>
 Explanation:

If run with the -trace flag it will show the steps take to check the spf
record, and if the -dns flag is added it will show all the DNS queries
involved.

 spf -help
 Usage of spf:
   -dns
     	show dns queries
   -from string
     	821.From address
   -helo string
     	domain used in 821.HELO
   -ip string
     	ip address from which the message is sent
   -mechanisms
    	show details about each mechanism
   -trace
     	show evaluation of record
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/wttw/spf"
)



func main() {
	var ip, from, domain, helo string
	var trace, showDns, mechanisms bool
	flag.StringVar(&ip, "ip", "", "ip address from which the message is sent")
	flag.StringVar(&from, "from", "", "821.From address")
	flag.StringVar(&helo, "helo", "", "domain used in 821.HELO")
	flag.BoolVar(&trace, "trace", false, "show evaluation of record")
	flag.BoolVar(&showDns, "dns", false, "show dns queries")
	flag.BoolVar(&mechanisms, "mechanisms", false, "show details about each mechanism")
	flag.Parse()

	if ip == "" {
		log.Fatalln("-ip is required")
	}

	if from == "" {
		log.Fatalln("-from is required")
	}

	if domain == "" {
		at := strings.LastIndex(from, "@")
		domain = from[at+1:]
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		log.Fatalf("'%s' doesn't look like an ip address", ip)
	}

	c := spf.NewChecker()
	if trace {
		au := aurora.NewAurora(isatty.IsTerminal(os.Stdout.Fd()))
		stdout := colorable.NewColorableStdout()
		c.Hook = &Tracer{
			au:             au,
			stdout:         stdout,
			dns:            showDns,
			showMechanisms: mechanisms,
			records:        map[string]spfMechanismResults{},
		}
	}
	ctx := context.Background()
	result := c.SPF(ctx, addr, from, helo)
	fmt.Printf("Result: %v\nError:  %v\nExplanation: %s\n", result.Type, result.Error, result.Explanation)
}

type spfMechanismResult struct {
	result    spf.ResultType
	mechanism spf.Mechanism
}

type spfMechanismResults struct {
	record            string
	results           map[int]spfMechanismResult
	associatedRecords []string
}

type Tracer struct {
	au                  aurora.Aurora
	stdout              io.Writer
	dns                 bool
	showMechanisms      bool
	lastMechanismDomain string
	records             map[string]spfMechanismResults
	depth               int
}

func (t *Tracer) resultColour(resultType spf.ResultType, msg string) aurora.Value {
	switch resultType {
	case spf.Temperror, spf.Permerror:
		return t.au.BrightRed(msg)
	case spf.None, spf.Neutral:
		return t.au.Blue(msg)
	case spf.Fail, spf.Softfail:
		return t.au.Red(msg)
	case spf.Pass:
		return t.au.Green(msg)
	}
	return t.au.BrightRed(fmt.Sprintf("unknown result type %v", resultType))
}

func (t *Tracer) resultString(resultType spf.ResultType) aurora.Value {
	return t.resultColour(resultType, resultType.String())
}

func (t *Tracer) Printf(format string, a ...interface{}) (int, error) {
	return fmt.Fprintf(t.stdout, format, a...)
}

var _ spf.Hook = &Tracer{}

func (t *Tracer) Dns(r *dns.Msg, m *dns.Msg, err error) {
	if t.dns {
		t.Printf("%s request for %s\n", dns.Type(r.Question[0].Qtype).String(), r.Question[0].Name)
		t.Printf("%s\n", t.au.Cyan(m.String()))
	}
}

func (t *Tracer) Macro(before, after string, err error) {
	if err == nil {
		if before != after {
			t.Printf("%s expands to %s\n", t.au.BgBlue(before), t.au.BgBlue(after))
		}
		return
	}

	t.Printf("%s %s: %s\n", t.au.BgRed("Failed to expand macro"), t.au.BgBlue(before), t.au.Red(err.Error()))
}

func (t *Tracer) Record(record, domain string) {
	t.depth++
	t.Printf("%s: %s\n", domain, t.au.Magenta(record))
	t.lastMechanismDomain = ""
	t.records[domain] = spfMechanismResults{
		record:  record,
		results: map[int]spfMechanismResult{},
	}
}

func (t *Tracer) Mechanism(domain string, index int, mechanism spf.Mechanism, result *spf.Result) {
	t.records[domain].results[index] = spfMechanismResult{
		result:    result.Type,
		mechanism: mechanism,
	}
	include, ok := mechanism.(spf.MechanismInclude)
	if ok {
		t.Printf("%s included %s", domain, include.DomainSpec)
		if result.Type == include.Qualifier {
			t.Printf(" which matched, so the include returned %s", t.resultString(result.Type))
		} else {
			t.Printf(" which didn't match")
		}
		t.Printf("\n")
	}
	if t.showMechanisms {
		if t.lastMechanismDomain != domain {
			t.Printf("from %s\n", domain)
			t.lastMechanismDomain = domain
		}
		t.Printf("  %2d ", index+1)
		switch result.Type {
		case spf.Temperror, spf.Permerror:
			t.Printf("%s %s", mechanism.String(), t.resultString(result.Type))
		case spf.None, spf.Neutral:
			t.Printf("%s (%s)", t.au.Blue(mechanism.String()), t.resultString(result.Type))
		case spf.Fail, spf.Softfail:
			t.Printf("%s (%s)", mechanism.String(), t.resultString(result.Type))
		case spf.Pass:
			t.Printf("%s (%s)", mechanism.String(), t.resultString(result.Type))
		}
		if result.Error != nil {
			t.Printf(" (%s)", t.au.Red(result.Error.Error()))
		}

		t.Printf("\n")
	}
}

var modifierRe = regexp.MustCompile(`^((?i)[a-z][a-z0-9_.-]*)=(.*)`)

func (t *Tracer) RecordResult(domain string, result *spf.Result) {
	t.depth--
	t.Printf("%s returns %s: ", domain, t.resultString(result.Type))
	spfRecord, ok := t.records[domain]
	if ok {
		fields := strings.Fields(spfRecord.record)
		i := 0
		for _, field := range fields {
			if modifierRe.MatchString(field) {
				t.Printf("%s ", field)
			} else {
				mech, ok := spfRecord.results[i]
				if !ok {
					t.Printf("%s ", t.au.Gray(15, field))
				} else {
					t.Printf("%s ", t.resultColour(mech.result, field))
				}
				i++
			}
		}
	}
	t.Printf("\n")
}

func (t *Tracer) Redirect(target string) {
	t.Printf("redirecting to %s\n", target)
}
