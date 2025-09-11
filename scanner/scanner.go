package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jsandas/starttls-go/starttls"
	"github.com/jsandas/tls-simulator/ftls"
)

type Scanner struct {
	Path              string
	Host              string
	Port              string
	Version           string
	Cipher            string
	Certificates      []*x509.Certificate // All certificates found in file/folder
	EntityCertificate *x509.Certificate   // Leaf certificate
	ChainCertificates []*x509.Certificate // Intermediate certificates
	skipStartTLS      bool                // for testing purposes
}

func NewScanner(host, port string) *Scanner {
	return &Scanner{
		Host: host,
		Port: port,
	}
}

// NewTestScanner creates a scanner that skips STARTTLS for testing.
func NewTestScanner(host, port string) *Scanner {
	return &Scanner{
		Host:         host,
		Port:         port,
		skipStartTLS: true,
	}
}

// CheckHost scans a host for TLS certificate information.
func (s *Scanner) CheckHost() error {
	log.Printf("Starting scanner on port %s", s.Port)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to servers
	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, s.Port))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Perform STARTTLS handshake if not skipped
	if !s.skipStartTLS {
		err := starttls.StartTLS(ctx, conn, s.Port)
		if err != nil {
			return fmt.Errorf("STARTTLS failed: %v", err)
		}
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName:         s.Host,
		InsecureSkipVerify: true, // #nosec G402 We are only interested in fetching certificates
		NextProtos:         []string{"http/1.1", "h2"},
		CipherSuites:       ftls.DefaultCipherSuites, // use all cipher suites supported by Go
	}

	// Upgrade connection to TLS
	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	s.Version = ftls.ProtocolToName[int(state.Version)]
	s.Cipher = ftls.CipherToName[state.CipherSuite]
	s.EntityCertificate = state.PeerCertificates[0]
	s.ChainCertificates = state.PeerCertificates[1:]

	return nil
}

// CheckPath scans a folder for TLS certificate information.
func (s *Scanner) CheckPath() error {
	log.Printf("Starting scanner in path %s", s.Path)

	// search for .pem, .crt, .cer files and parse certificates in a folder
	files, err := os.ReadDir(s.Path)
	if err != nil {
		return fmt.Errorf("failed to read folder: %v", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if strings.HasSuffix(file.Name(), ".pem") || strings.HasSuffix(file.Name(), ".crt") ||
			strings.HasSuffix(file.Name(), ".cer") || strings.HasSuffix(file.Name(), ".der") {
			filePath := fmt.Sprintf("%s/%s", s.Path, file.Name())

			certs, err := parseFile(filePath)
			if err != nil {
				log.Printf("Failed to read file %s: %v", filePath, err)
				continue
			}

			s.Certificates = append(s.Certificates, certs...)

			log.Printf("Parsed certificates from file %s", filePath)
		}
	}

	return nil
}
