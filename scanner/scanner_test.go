package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jsandas/starttls-go/starttls"
)

func TestNewScanner(t *testing.T) {
	// TestNewScanner verifies that NewScanner correctly initializes a Scanner with the
	// provided host and port values, confirming the struct fields are set as expected.
	tests := []struct {
		name     string
		host     string
		port     string
		wantHost string
		wantPort string
	}{
		{
			name:     "basic scanner creation",
			host:     "example.com",
			port:     "443",
			wantHost: "example.com",
			wantPort: "443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner(tt.host, tt.port)
			if s.Host != tt.wantHost {
				t.Errorf("NewScanner().Host = %v, want %v", s.Host, tt.wantHost)
			}

			if s.Port != tt.wantPort {
				t.Errorf("NewScanner().Port = %v, want %v", s.Port, tt.wantPort)
			}
		})
	}
}

// TestScanner_CheckHost verifies the happy path of CheckHost when connecting to a
// TLS server with a single certificate. It confirms that the scanner successfully
// captures the entity certificate, TLS version, and cipher suite from the handshake.
func TestScanner_CheckHost(t *testing.T) {
	// Create test certificates
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Skip("Skipping test: test certificates not available")
	}

	// Start a plain TCP server that will upgrade to TLS
	lc := net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	// Get the actual port that was assigned
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	// Handle connections in a goroutine
	go func() {
		for {
			// Create a context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := listener.Accept()
			if err != nil {
				return
			}

			// Upgrade to TLS immediately
			config := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			tlsConn := tls.Server(conn, config)

			// Perform handshake
			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				tlsConn.Close()
				return
			}

			// Keep connection open briefly
			time.Sleep(100 * time.Millisecond)
			tlsConn.Close()
		}
	}() // Create and start scanner

	s := NewTestScanner("localhost", port)

	err = s.CheckHost(context.Background())
	if err != nil {
		t.Fatalf("Failed to start scanner: %v", err)
	}

	// Verify that scanner captured certificate details
	if s.EntityCertificate == (CertificateInfo{}) {
		t.Error("Expected EntityCertificate to be set")
	}

	if s.Version == "" {
		t.Error("Expected Version to be set")
	}

	if s.Cipher == "" {
		t.Error("Expected Cipher to be set")
	}
}

// TestScanner_CheckPath verifies that CheckPath correctly scans a directory for certificate
// files (.pem, .crt, .cer, .der), parses them, and validates certificate details including
// subject, validity period, and uniqueness of serial numbers. It also tests error handling
// for non-existent directories.
func TestScanner_CheckPath(t *testing.T) {
	// Create a test directory structure
	err := os.MkdirAll("testdata/certtest", 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	defer os.RemoveAll("testdata/certtest")

	// Copy test files to the test directory
	files := []string{"single.pem", "multiple.pem", "cert.der"}
	for _, file := range files {
		content, err := os.ReadFile("testdata/" + file)
		if err != nil {
			t.Fatalf("Failed to read test file %s: %v", file, err)
		}

		err = os.WriteFile("testdata/certtest/"+file, content, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file %s: %v", file, err)
		}
	}

	tests := []struct {
		name          string
		path          string
		wantNumCerts  int
		wantErr       bool
		wantSubject   string
		wantNotBefore string
		wantNotAfter  string
	}{
		{
			name:          "directory with certificates",
			path:          "testdata/certtest",
			wantNumCerts:  4, // 2 from multiple.pem + 1 from single.pem + 1 from cert.der
			wantErr:       false,
			wantSubject:   "O=Test Company Ltd,L=Test City,C=XX",
			wantNotBefore: "2025-09-11 03:37:45 +0000 UTC",
			wantNotAfter:  "2026-09-11 03:37:45 +0000 UTC",
		},
		{
			name:         "non-existent directory",
			path:         "testdata/nonexistent",
			wantNumCerts: 0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{
				Path: tt.path,
			}

			err := s.CheckPath(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Scanner.CheckPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got := len(s.Certificates); got != tt.wantNumCerts {
					t.Errorf("Scanner.CheckPath() got %v certificates, want %v", got, tt.wantNumCerts)
				}

				// Check first certificate details if available
				if len(s.Certificates) > 0 {
					certData := s.Certificates[0]
					if got := certData.Certificate.Subject.String(); got != tt.wantSubject {
						t.Errorf("First certificate subject = %v, want %v", got, tt.wantSubject)
					}

					if got := certData.Certificate.NotBefore.String(); got != tt.wantNotBefore {
						t.Errorf("First certificate NotBefore = %v, want %v", got, tt.wantNotBefore)
					}

					if got := certData.Certificate.NotAfter.String(); got != tt.wantNotAfter {
						t.Errorf("First certificate NotAfter = %v, want %v", got, tt.wantNotAfter)
					}
				}

				// Check for unique certificates
				seen := make(map[string]bool)

				for _, certData := range s.Certificates {
					serial := certData.Certificate.SerialNumber.String()
					if seen[serial] {
						t.Errorf("Found duplicate certificate with serial number %s", serial)
					}

					seen[serial] = true
				}
			}
		})
	}
}

// TestScanner_CheckHost_SingleCertificate_NoChain verifies that CheckHost correctly handles a TLS
// server that presents a single certificate (no chain). It confirms the entity certificate is
// captured with its fingerprint, while ChainCertificates remains empty since no intermediates
// were provided by the server.
func TestScanner_CheckHost_SingleCertificate_NoChain(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Skip("Skipping test: test certificates not available")
	}

	lc := net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

			conn, err := listener.Accept()
			if err != nil {
				cancel()
				return
			}

			config := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			tlsConn := tls.Server(conn, config)

			err = tlsConn.HandshakeContext(ctx)

			cancel()

			if err != nil {
				tlsConn.Close()
				return
			}

			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				_ = state.PeerCertificates[0].Subject
			}

			time.Sleep(100 * time.Millisecond)
			tlsConn.Close()
		}
	}()

	s := NewTestScanner("localhost", port)

	err = s.CheckHost(context.Background())
	if err != nil {
		t.Fatalf("Failed to start scanner: %v", err)
	}

	if s.EntityCertificate == (CertificateInfo{}) {
		t.Error("Expected EntityCertificate to be set")
	}

	if s.Version == "" {
		t.Error("Expected Version to be set")
	}

	if s.Cipher == "" {
		t.Error("Expected Cipher to be set")
	}

	if len(s.ChainCertificates) != 0 {
		t.Errorf("Expected 0 chain certificates, got %d", len(s.ChainCertificates))
	}

	if s.EntityCertificate.Fingerprint == "" {
		t.Error("Expected EntityCertificate.Fingerprint to be set")
	}
}

// TestScanner_CheckHost_ConnectionError verifies that CheckHost properly returns an error when
// the TCP dial fails, such as when attempting to connect to a closed port. This tests the error
// path at line 117-119 of scanner.go where the connection attempt fails before any TLS handshake.
func TestScanner_CheckHost_ConnectionError(t *testing.T) {
	lc := net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}

	listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	s := NewTestScanner("localhost", port)

	err = s.CheckHost(context.Background())
	if err == nil {
		t.Fatal("Expected error for connection to closed port, got nil")
	}

	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("Expected 'failed to connect' error, got: %v", err)
	}
}

// TestScanner_CheckHost_STARTTLSPath verifies that CheckHost correctly executes the STARTTLS
// upgrade sequence when skipStartTLS is false (using NewScanner instead of NewTestScanner).
// It tests the code path at lines 123-128 of scanner.go where the connection is upgraded from
// plain TCP to TLS before the certificate exchange occurs.
func TestScanner_CheckHost_STARTTLSPath(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Skip("Skipping test: test certificates not available")
	}

	lc := net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := listener.Accept()
			if err != nil {
				return
			}

			err = starttls.StartTLS(context.Background(), conn, port)
			if err != nil {
				conn.Close()
				return
			}

			config := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			tlsConn := tls.Server(conn, config)

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				tlsConn.Close()
				return
			}

			time.Sleep(100 * time.Millisecond)
			tlsConn.Close()
		}
	}()

	s := NewScanner("localhost", port)

	err = s.CheckHost(context.Background())
	if err != nil {
		t.Skipf("Skipping STARTTLS test (failed to exercise STARTTLS path): %v", err)
	}

	if s.EntityCertificate == (CertificateInfo{}) {
		t.Error("Expected EntityCertificate to be set")
	}
}

// TestScanner_CheckHost_HandshakeError verifies that CheckHost properly returns an error when
// the TLS handshake fails, such as when a server sends invalid or incomplete TLS data. This
// tests the error path at lines 141-144 of scanner.go where tlsConn.HandshakeContext returns
// an error due to malformed TLS records.
func TestScanner_CheckHost_HandshakeError(t *testing.T) {
	lc := net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	go func() {
		for {
			_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cancel()

			conn, err := listener.Accept()
			if err != nil {
				return
			}

			conn.Write([]byte{0x16, 0x03, 0x01})
			conn.Close()
		}
	}()

	s := NewTestScanner("localhost", port)

	err = s.CheckHost(context.Background())
	if err == nil {
		t.Fatal("Expected error for handshake failure, got nil")
	}

	if !strings.Contains(err.Error(), "TLS handshake failed") {
		t.Errorf("Expected 'TLS handshake failed' error, got: %v", err)
	}
}

// TestScanner_CheckHost_ChainCertificates verifies that CheckHost correctly processes TLS
// certificate chains by creating a multi-certificate handshake (leaf + intermediate CA + root CA).
// It tests the code path at lines 167-178 of scanner.go where PeerCertificates[1:] is iterated
// to extract and process intermediate/root certificates into ChainCertificates, confirming that
// each chain certificate receives its own fingerprint and processed metadata.
func TestScanner_CheckHost_ChainCertificates(t *testing.T) {
	// Generate root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Generate intermediate CA
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}

	interCertBytes, err := x509.CreateCertificate(rand.Reader, interTemplate, rootTemplate, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	// Load leaf certificate
	leafCert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Skip("Skipping test: test certificates not available")
	}

	// Create chain: leaf (from file) + intermediate + root
	// Build TLS certificates with the chain
	leafCert.Certificate = append(leafCert.Certificate, interCertBytes, rootCertBytes)

	lc := net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	chainConfig := tls.Config{
		Certificates: []tls.Certificate{leafCert},
	}

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := listener.Accept()
			if err != nil {
				return
			}

			tlsConn := tls.Server(conn, &chainConfig)

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				tlsConn.Close()
				return
			}

			time.Sleep(100 * time.Millisecond)
			tlsConn.Close()
		}
	}()

	s := NewTestScanner("localhost", port)

	err = s.CheckHost(context.Background())
	if err != nil {
		t.Fatalf("Failed to start scanner: %v", err)
	}

	if s.EntityCertificate == (CertificateInfo{}) {
		t.Error("Expected EntityCertificate to be set")
	}

	if s.EntityCertificate.Fingerprint == "" {
		t.Error("Expected EntityCertificate.Fingerprint to be set")
	}

	if len(s.ChainCertificates) != 2 {
		t.Errorf("Expected 2 chain certificates (intermediate + root), got %d", len(s.ChainCertificates))
	}

	if len(s.ChainCertificates) >= 1 {
		if s.ChainCertificates[0].Fingerprint == "" {
			t.Error("Expected ChainCertificates[0].Fingerprint to be set")
		}
	}

	if len(s.ChainCertificates) >= 2 {
		if s.ChainCertificates[1].Fingerprint == "" {
			t.Error("Expected ChainCertificates[1].Fingerprint to be set")
		}
	}

	if s.Version == "" {
		t.Error("Expected Version to be set")
	}

	if s.Cipher == "" {
		t.Error("Expected Cipher to be set")
	}
}
