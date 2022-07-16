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

## Use as a CLI tool

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

```shell
./spf -trace -from n_e_i_bounces@insideapple.apple.com -ip 17.179.250.63
insideapple.apple.com.: v=spf1 include:_spf-txn.apple.com include:_spf-mkt.apple.com include:_spf.apple.com ~all
_spf-txn.apple.com.: v=spf1 ip4:17.151.1.0/24 ip4:17.171.37.0/24 ip4:17.111.110.0/23 ~all
_spf-txn.apple.com. returns softfail: v=spf1 ip4:17.151.1.0/24 ip4:17.171.37.0/24 ip4:17.111.110.0/23 ~all
insideapple.apple.com. included _spf-txn.apple.com which didn't match
_spf-mkt.apple.com.: v=spf1 ip4:17.171.23.0/24 ip4:17.179.250.0/24 ip4:17.32.227.0/24 ip4:17.240.6.0/24 ip4:17.240.49.0/24 ~all
_spf-mkt.apple.com. returns pass: v=spf1 ip4:17.171.23.0/24 ip4:17.179.250.0/24 ip4:17.32.227.0/24 ip4:17.240.6.0/24 ip4:17.240.49.0/24 ~all
insideapple.apple.com. included _spf-mkt.apple.com which matched, so the include returned pass
insideapple.apple.com. returns pass: v=spf1 include:_spf-txn.apple.com include:_spf-mkt.apple.com include:_spf.apple.com ~all
Result: pass
Error:  <nil>
Explanation:
```

### Installing binaries

Binary releases of the commandline tool `spf` are available under [Releases](https://github.com/wttw/spf/releases).

You'll need to unpack them with `tar zxf spf-<stuff>.tar.gz` or unzip the Windows packages.

These are built automatically and right now the workflow doesn't sign the binaries. You'll need to bypass
the check for that, e.g. on macOS open it in finder, right click on it and select `Open` then give permission
for it to run.

## Use as a library

```go
import "github.com/wttw/spf"

ip := net.ParseIP("8.8.8.8")
result, _ := spf.Check(context.Background(), ip, "steve@aol.com", "aol.com")
fmt.Println(result)
```
