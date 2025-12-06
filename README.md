# cert-finder

[![CI](https://github.com/jsandas/cert-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/jsandas/cert-finder/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jsandas/cert-finder)](https://goreportcard.com/report/github.com/jsandas/cert-finder)
[![GoDoc](https://godoc.org/github.com/jsandas/cert-finder?status.svg)](https://godoc.org/github.com/jsandas/cert-finder)

A Go library for retrieving TLS certificate information from remote servers. Built on top of [starttls-go](https://github.com/jsandas/starttls-go) for seamless STARTTLS protocol support.

## Features

- **Dual Operation Modes**: 
  - Remote scanning with automatic protocol detection (direct TLS and STARTTLS)
  - Local certificate file/directory scanning (PEM and DER formats)
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

The library supports two main modes of operation:

### Remote Certificate Scanning

```go
package main

import (
    "fmt"
    "log"

    "github.com/jsandas/cert-finder/scanner"
)

func main() {
    // Create a scanner for remote host
    s := scanner.NewScanner("example.com", "443")
    // Optionally exclude raw OCSP/CRL response data to save memory
    s.IncludeStatusData = false // set to true if you need raw response bytes

    // Scan remote host
    err := s.CheckHost()
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Access connection details
    fmt.Printf("TLS Version: %s\n", s.Version)
    fmt.Printf("Cipher Suite: %s\n", s.Cipher)
    
    // Access certificate information
    fmt.Printf("Subject: %s\n", s.EntityCertificate.Subject)
    fmt.Printf("Issuer: %s\n", s.EntityCertificate.Issuer)
    fmt.Printf("Not After: %s\n", s.EntityCertificate.NotAfter)
}
```

### Local Certificate File Scanning

```go
package main

import (
    "fmt"
    "log"

    "github.com/jsandas/cert-finder/scanner"
)

func main() {
    // Create a scanner for local files
    s := &scanner.Scanner{
        Path: "/path/to/certs",
    }
    // Optionally include OCSP/CRL raw response data
    s.IncludeStatusData = false
    
    // Scan directory for certificates
    err := s.CheckPath()
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Process found certificates
    for i, cert := range s.Certificates {
        fmt.Printf("Certificate %d:\n", i+1)
        fmt.Printf("  Subject: %s\n", cert.Subject)
        fmt.Printf("  Issuer: %s\n", cert.Issuer)
        fmt.Printf("  Not After: %s\n", cert.NotAfter)
    }
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

## Supported File Formats

When scanning local certificates, the following formats are supported:

| Format | File Extensions | Description |
|--------|----------------|-------------|
| PEM    | .pem, .crt, .cer | Base64 encoded certificates with BEGIN/END markers |
| DER    | .der           | Binary encoded X.509 certificates |

## Testing

The package includes testing utilities for both remote and local certificate scanning:

```go
// Test remote scanning (skips STARTTLS)
s := scanner.NewTestScanner("localhost", "8443")
err := s.CheckHost()

// Test local certificate scanning
s := &scanner.Scanner{
    Path: "testdata/certs",
}
err := s.CheckPath()
```

Run the test suite:
```bash
go test -v ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.