[![](https://godoc.org/github.com/wttw/spf?status.svg)](https://godoc.org/github.com/wttw/spf)

# A library to evaluate SPF policy records

Complete, usable library to check whether a received email passes a
published SPF (Sender Policy Framework) policy.

It implements all of the SPF checker protocol as described in
[RFC 7208](https://tools.wordtothewise.com/rfc7208), including macros and 
PTR checks, and passes 100% of the openspf and pyspf test suites.

A DNS stub resolver using [miekg/dns](https://github.com/miekg/dns) is
included, but can be replaced by anything that implements the
spf.Resolver interface.

As well as providing an implementation of the SPF check_host() function it
also provides hooks to instrument the checking process. The included example
client uses these to show how an SPF record is evaluated.

```shell
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
```

```go
import "github.com/wttw/spf"

ip := net.ParseIP("8.8.8.8")
result, _ := spf.Check(context.Background(), ip, "steve@aol.com", "aol.com")
fmt.Println(result)
```
