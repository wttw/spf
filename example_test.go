package spf_test

import (
	"context"
	"fmt"
	"net"

	"github.com/wttw/spf/v2"
)

func ExampleCheck() {
	ip := net.ParseIP("8.8.8.8")
	result, _ := spf.Check(context.Background(), ip, "steve@aol.com", "aol.com")
	fmt.Println(result)
	// Output: neutral
}

func ExampleChecker_SPF() {
	ip := net.ParseIP("8.8.8.8")
	c := spf.NewChecker()
	c.Hostname = "mail.example.com"
	result := c.SPF(context.Background(), ip, "steve@aol.com", "aol.com")
	fmt.Printf("Authentication-Results: %s\n", result.AuthenticationResults())
	// Output: Authentication-Results: mail.example.com; spf=neutral smtp.mailfrom=steve@aol.com
}
