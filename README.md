# cert-finder

[![CI](https://github.com/jsandas/cert-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/jsandas/cert-finder/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jsandas/cert-finder)](https://goreportcard.com/report/github.com/jsandas/cert-finder)
[![GoDoc](https://godoc.org/github.com/jsandas/cert-finder?status.svg)](https://godoc.org/github.com/jsandas/cert-finder)

A Go library for retrieving TLS certificate information from remote servers. Built on top of [starttls-go](https://github.com/jsandas/starttls-go) for seamless STARTTLS protocol support.

## Features

- **Automatic Protocol Detection**: Seamlessly handles both direct TLS and STARTTLS connections
- **Comprehensive Certificate Information**: Retrieves complete certificate chains and details
- **Modern TLS Support**: Compatible with TLS 1.2 and 1.3
- **Rich Connection Details**: Reports negotiated protocol versions and cipher suites
- **Built-in Safety**: Implements connection timeouts and context cancellation
- **Testing Support**: Includes utilities for testing TLS connections

## Installation

```bash
go get github.com/jsandas/cert-finder
```

## Usage

Basic example:
```go
package main

import (
    "fmt"
    "log"

    "github.com/jsandas/cert-finder/scanner"
)

func main() {
    // Create a new scanner
    s := scanner.NewScanner("example.com", "443")
    
    // Start the scan
    err := s.Start()
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Access results
    fmt.Printf("TLS Version: %s\n", s.Version)
    fmt.Printf("Cipher Suite: %s\n", s.Cipher)
    fmt.Printf("Subject: %s\n", s.EntityCertificate.Subject)
    fmt.Printf("Issuer: %s\n", s.EntityCertificate.Issuer)
    fmt.Printf("Not After: %s\n", s.EntityCertificate.NotAfter)
}
```

## Protocol Support

Automatically detects and handles:

| Protocol | Default Ports | Notes |
|----------|--------------|-------|
| HTTPS    | 443          | Direct TLS |
| SMTP     | 25, 587      | STARTTLS |
| IMAP     | 143          | STARTTLS |
| POP3     | 110          | STARTTLS |
| FTP      | 21           | STARTTLS |
| XMPP     | 5222         | STARTTLS |

## Testing

The package includes testing utilities for mocking TLS servers:

```go
// Create a test scanner that skips STARTTLS
s := scanner.NewTestScanner("localhost", "8443")

// Run your tests
err := s.Start()
```

Run the test suite:
```bash
go test -v ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.