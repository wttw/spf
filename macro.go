package spf

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 7.  Macros (RFC 7208)
//
//   When evaluating an SPF policy record, certain character sequences are
//   intended to be replaced by parameters of the message or of the
//   connection.  These character sequences are referred to as "macros".
//
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
//   explain-string   = *( macro-string / SP )
//
//   macro-string     = *( macro-expand / macro-literal )
//   macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
//                      / "%%" / "%_" / "%-"
//   macro-literal    = %x21-24 / %x26-7E
//                      ; visible characters except "%"
//   macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
//                      "c" / "r" / "t" / "v"
//   transformers     = *DIGIT [ "r" ]
//   delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
//
//   The "toplabel" construction is subject to the letter-digit-hyphen
//   (LDH) rule plus additional top-level domain (TLD) restrictions.  See
//   Section 2 of [RFC3696] for background.
//
//   Some special cases:
//
//   o  A literal "%" is expressed by "%%".
//
//   o  "%_" expands to a single " " space.
//
//   o  "%-" expands to a URL-encoded space, viz., "%20".
//
// 7.2.  Macro Definitions
//
//   The following macro letters are expanded in term arguments:
//
//      s = <sender>
//      l = local-part of <sender>
//      o = domain of <sender>
//      d = <domain>
//      i = <ip>
//      p = the validated domain name of <ip> (do not use)
//      v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
//      h = HELO/EHLO domain
//
//   <domain>, <sender>, and <ip> are defined in Section 4.1.
//
//   The following macro letters are allowed only in "exp" text:
//
//      c = SMTP client IP (easily readable format)
//      r = domain name of host performing the check
//      t = current timestamp

var macroRe = regexp.MustCompile(`^{([alodiphcrtvALODIPHCRTV])([0-9]{0,3})(r?)([.+=,/_-]*)}`)

// MacroIsValid validates an SPF macro.
func MacroIsValid(macroString string) bool {
	for {
		percent := strings.Index(macroString, "%")
		if percent == -1 {
			return true
		}
		macroString = macroString[percent+1:]
		if len(macroString) == 0 {
			return false
		}
		switch macroString[0] {
		case '%', '-', '_':
			macroString = macroString[1:]
		default:
			return false
		case '{':
			matches := macroRe.FindStringSubmatch(macroString)
			if matches == nil {
				return false
			}
			macroString = macroString[len(matches[0]):]
		}
	}
}

// ExpandMacro populates an SPF macro based on the current state of the check process.
func (c *Checker) ExpandMacro(ctx context.Context, domainSpec string, result *Result, domain string, exp bool) (string, error) {
	expansion, err := c.expandMacro(ctx, domainSpec, result, domain, exp)
	if c.Hook != nil {
		c.Hook.Macro(domainSpec, expansion, err)
	}
	return expansion, err
}

func (c *Checker) expandMacro(ctx context.Context, domainSpec string, result *Result, domain string, exp bool) (string, error) {
	percent := strings.Index(domainSpec, "%")
	if percent == -1 {
		// short circuit common case
		return domainSpec, nil
	}
	var ret strings.Builder
	for {
		ret.WriteString(domainSpec[:percent])
		domainSpec = domainSpec[percent+1:]
		if len(domainSpec) == 0 {
			return "", errors.New("trailing % in macro expansion")
		}
		switch domainSpec[0] {
		case '%':
			ret.WriteRune('%')
			domainSpec = domainSpec[1:]
		case '-':
			ret.WriteString("%20")
			domainSpec = domainSpec[1:]
		case '_':
			ret.WriteRune(' ')
			domainSpec = domainSpec[1:]
		default:
			return "", fmt.Errorf("invalid character '%c' following %% in macro expansion", domainSpec[0])
		case '{':
			matches := macroRe.FindStringSubmatch(domainSpec)
			if len(matches) == 0 {
				return "", fmt.Errorf("invalid macro starting near %s", domainSpec)
			}
			macroLetter, macroLimit, macroReverse, macroDelimiters := matches[1], matches[2], matches[3], matches[4]
			domainSpec = domainSpec[len(matches[0]):]
			var replacement string
			switch strings.ToLower(macroLetter) {
			case "s":
				replacement = result.sender
			case "l":
				replacement = result.sender[:strings.LastIndex(result.sender, "@")]
			case "o":
				replacement = strings.TrimSuffix(result.sender[strings.LastIndex(result.sender, "@")+1:], ".")
			case "d":
				replacement = strings.TrimSuffix(domain, ".")
			case "i":
				if result.ip.To4() == nil {
					v6 := result.ip.To16()
					enc := make([]byte, 32)
					hex.Encode(enc, v6)
					var buff bytes.Buffer
					for i, b := range enc {
						if i != 0 {
							buff.Write([]byte{'.'})
						}
						buff.Write([]byte{b})
					}
					replacement = buff.String()
				} else {
					replacement = result.ip.String()
				}
			case "p":
				replacement = expandPtrMacro(ctx, result, domain)
			case "h":
				replacement = result.helo
			case "c":
				if !exp {
					return "", errors.New("c macro not allowed outside exp")
				}
				replacement = result.ip.String()
			case "r":
				if !exp {
					return "", errors.New("r macro not allowed outside exp")
				}
				replacement = c.Hostname
			case "t":
				if !exp {
					return "", errors.New("t macro not allowed outside exp")
				}
				replacement = strconv.FormatInt(time.Now().Unix(), 10)
			case "v":
				if result.ip.To4() == nil {
					replacement = "ip6"
				} else {
					replacement = "in-addr"
				}
			default:
				return "", fmt.Errorf("can't happen: impossible macro-letter: %s", macroLetter)
			}

			if macroLetter[0] >= 'A' && macroLetter[0] <= 'Z' {
				replacement = rfc3986Escape(replacement)
			}
			if macroLimit != "" || macroReverse != "" || macroDelimiters != "" {
				if macroDelimiters == "" {
					macroDelimiters = "."
				}
				parts := []string{}
				for {
					delimiter := strings.IndexAny(replacement, macroDelimiters)
					if delimiter == -1 {
						parts = append(parts, replacement)
						break
					}
					parts = append(parts, replacement[:delimiter])
					replacement = replacement[delimiter+1:]
				}
				if macroReverse != "" {
					for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
						parts[i], parts[j] = parts[j], parts[i]
					}
				}
				if macroLimit != "" {
					limit, err := strconv.Atoi(macroLimit)
					if err == nil && limit < len(parts) {
						parts = parts[len(parts)-limit:]
					}
				}
				replacement = strings.Join(parts, ".")
			}

			ret.WriteString(replacement)
		}

		percent = strings.Index(domainSpec, "%")
		if percent == -1 {
			ret.WriteString(domainSpec)
			return ret.String(), nil
		}
	}
}

// ExpandDomainSpec expands a domain-spec as an SPF macro, then checks that
// the result is a valid-appearing hostname.
func (c *Checker) ExpandDomainSpec(ctx context.Context, domainSpec string, result *Result, domain string, exp bool) (string, error) {
	if domainSpec == "" {
		return domain, nil
	}
	target, err := c.ExpandMacro(ctx, domainSpec, result, domain, exp)
	if err != nil {
		return target, err
	}
	length := len(target)
	if length <= 253 {
		return target, nil
	}
	parts := strings.Split(target, ".")
	for {
		if len(parts) == 0 {
			return "", errors.New("oddly long TLD")
		}
		length = length - len(parts[0]) - 1
		parts = parts[1:]
		if length <= 253 {
			return strings.Join(parts, "."), nil
		}
	}
}

//  7.3.  Macro Processing Details (rfc 7208)
//   Uppercase macros expand exactly as their lowercase equivalents, and
//   are then URL escaped.  URL escaping MUST be performed for characters
//   not in the "unreserved" set, which is defined in [RFC3986].

// 2.3.  Unreserved Characters (rfc 3986)
//
//   Characters that are allowed in a URI but do not have a reserved
//   purpose are called unreserved.  These include uppercase and lowercase
//   letters, decimal digits, hyphen, period, underscore, and tilde.
//
//      unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"

const upperhex = "0123456789ABCDEF"

// I don't trust url.*Escape to do the right thing
// code snarfed from url.escape()
func rfc3986Escape(s string) string {
	hexCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			hexCount++
		}
	}
	if hexCount == 0 {
		return s
	}
	var buf [64]byte
	var t []byte

	required := len(s) + 2*hexCount
	if required <= len(buf) {
		t = buf[:required]
	} else {
		t = make([]byte, required)
	}

	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = upperhex[c>>4]
			t[j+2] = upperhex[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func shouldEscape(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z':
		return false
	case 'a' <= c && c <= 'z':
		return false
	case '0' <= c && c <= '9':
		return false
	}
	switch c {
	case '-', '.', '_', '~':
		return false
	}
	return true
}
