package main

import (
	"context"
	"fmt"

	"github.com/jsandas/cert-finder/scanner"
)

func main() {

	test := scanner.NewScanner("www.google.com", "443")
	err := test.CheckHost(context.Background())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Protocol Version: %s\n", test.Version)
	fmt.Printf("Cipher Suite: %s\n", test.Cipher)
	fmt.Printf("Entity Certificate: %v\n", test.EntityCertificate)
	fmt.Printf("Chain Certificates: %v\n", test.ChainCertificates)
}
