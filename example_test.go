package spf_test

import (
	"context"
	"fmt"
	"net"

	"github.com/wttw/spf"
)

func ExampleCheck() {
	ip := net.ParseIP("8.8.8.8")
	result, _ := spf.Check(context.Background(), ip, "steve@aol.com", "aol.com")
	fmt.Println(result)
	// Output: softfail
}

func ExampleChecker_SPF() {
	ip := net.ParseIP("8.8.8.8")
	c := spf.NewChecker()
	c.Hostname = "mail.example.com"
	result := c.SPF(context.Background(), ip, "steve@aol.com", "aol.com")
	fmt.Printf("Authentication-Results: %s\n", result.AuthenticationResults())
	// Output: Authentication-Results: mail.example.com; spf=softfail smtp.helo=aol.com
}
