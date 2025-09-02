package main

import (
	"fmt"

	"github.com/jsandas/cert-finder/scanner"
)

const ()

func main() {

	test := scanner.NewScanner("www.google.com", "443")
	test.Start()

	fmt.Printf("Protocol Version: %s\n", test.Version)
	fmt.Printf("Cipher Suite: %s\n", test.Cipher)
	fmt.Printf("Entity Certificate: %v\n", test.EntityCertificate)
	fmt.Printf("Chain Certificates: %v\n", test.ChainCertificates)
}
