package scanner

import (
	"crypto/tls"
	"net"
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

func TestScanner_Start(t *testing.T) {
	// Create test certificates
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Skip("Skipping test: test certificates not available")
	}

	// Start a plain TCP server that will upgrade to TLS
	listener, err := net.Listen("tcp", "localhost:0")
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
			if err := tlsConn.Handshake(); err != nil {
				tlsConn.Close()
				return
			}

			// Keep connection open briefly
			time.Sleep(100 * time.Millisecond)
			tlsConn.Close()
		}
	}() // Create and start scanner
	s := NewTestScanner("localhost", port)
	s.Start()

	// Verify that scanner captured certificate details
	if s.EntityCertificate == nil {
		t.Error("Expected EntityCertificate to be set")
	}
	if s.Version == "" {
		t.Error("Expected Version to be set")
	}
	if s.Cipher == "" {
		t.Error("Expected Cipher to be set")
	}
}
