/*
Package spf implements an SPF checker to evaluate whether or not an email
messages passes a published SPF (Sender Policy Framework) policy.

It implements all of the SPF checker protocol as described in RFC 7208, including
macros and PTR checks, and passes 100% of the openspf and pyspf test suites.

A DNS stub resolver is included, but can be replaced by anything that implements
the spf.Resolver interface.

The Hook interface can be used to hook into the check_host function to see more
details about why a policy passes or fails.
*/
package spf
