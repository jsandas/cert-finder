package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
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

	err = s.CheckHost()
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

			err := s.CheckPath()
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
