package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jsandas/starttls-go/starttls"
	"github.com/jsandas/tls-simulator/ftls"
)

type Scanner struct {
	Host              string
	Port              string
	Version           string
	Cipher            string
	EntityCertificate *x509.Certificate
	ChainCertificates []*x509.Certificate
	skipStartTLS      bool // for testing purposes
}

func NewScanner(host string, port string) *Scanner {
	return &Scanner{
		Host: host,
		Port: port,
	}
}

// NewTestScanner creates a scanner that skips STARTTLS for testing
func NewTestScanner(host string, port string) *Scanner {
	return &Scanner{
		Host:         host,
		Port:         port,
		skipStartTLS: true,
	}
}

func (s *Scanner) Start() {
	log.Printf("Starting scanner on port %s", s.Port)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to server
	conn, err := net.Dial("tcp", net.JoinHostPort(s.Host, s.Port))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Perform STARTTLS handshake if not skipped
	if !s.skipStartTLS {
		if err := starttls.StartTLS(ctx, conn, s.Port); err != nil {
			log.Fatalf("STARTTLS failed: %v", err)
		}
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName:         s.Host,
		InsecureSkipVerify: true, // We are only interested in fetching certificates
		NextProtos:         []string{"http/1.1", "h2"},
		CipherSuites:       ftls.DefaultCipherSuites, // use all cipher suites supported by Go
	}

	// Upgrade connection to TLS
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}
	defer tlsConn.Close()

	fmt.Println("Successfully established TLS connection!")

	state := tlsConn.ConnectionState()
	s.Version = ftls.ProtocolToName[int(state.Version)]
	s.Cipher = ftls.CipherToName[state.CipherSuite]
	s.EntityCertificate = state.PeerCertificates[0]
	s.ChainCertificates = state.PeerCertificates[1:]
	log.Printf("Negotiated Protocol: %s", state.NegotiatedProtocol)

	log.Printf("Successfully established TLS connection on port %s", s.Port)
}
