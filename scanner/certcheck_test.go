package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestCheckCertStatus(t *testing.T) {
	// Create a test issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{1, 2, 3}, // This should match AuthorityKeyId in test certs
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Self-sign the issuer certificate
	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate,
		issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer certificate: %v", err)
	}

	// Parse the issuer certificate for later use
	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer certificate: %v", err)
	}

	// Setup mock issuer server
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer issuerServer.Close()

	// Create and setup OCSP server
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ocsp.Response{
			Status:     ocsp.Good,
			NextUpdate: time.Now().Add(24 * time.Hour),
			ThisUpdate: time.Now(),
		}

		respBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, resp, issuerKey)
		if err != nil {
			t.Fatalf("Failed to create OCSP response: %v", err)
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	}))
	defer ocspServer.Close()

	// Create and setup CRL server
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlBytes)
	}))
	defer crlServer.Close()

	tests := []struct {
		name          string
		cert          *x509.Certificate
		wantValid     bool
		wantOCSPError bool
		wantCRLError  bool
		wantErr       bool
	}{
		{
			name: "expired certificate",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-48 * time.Hour),
				NotAfter:              time.Now().Add(-24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
			},
			wantValid: false,
		},
		{
			name: "not yet valid certificate",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(24 * time.Hour),
				NotAfter:              time.Now().Add(48 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
			},
			wantValid: false,
		},
		{
			name: "certificate with no AIA",
			cert: &x509.Certificate{
				NotBefore: time.Now().Add(-24 * time.Hour),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "certificate with unreachable issuer",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://invalid.example.com"},
			},
			wantErr: true,
		},
		{
			name: "valid certificate with no OCSP/CRL",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
			},
			wantValid: true,
		},
		{
			name: "valid certificate with OCSP",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				OCSPServer:            []string{ocspServer.URL},
			},
			wantValid: true,
		},
		{
			name: "valid certificate with CRL",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{crlServer.URL},
			},
			wantValid: true,
		},
		{
			name: "valid certificate with LDAP CRL",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{"ldap://example.com/cn=crl"},
			},
			wantValid: true,
		},
		{
			name: "certificate with unreachable OCSP",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				OCSPServer:            []string{"http://invalid.example.com"},
			},
			wantValid:     true,
			wantOCSPError: true,
		},
		{
			name: "certificate with unreachable CRL",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{"http://invalid.example.com"},
			},
			wantValid:    true,
			wantCRLError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := CheckCertStatus(tt.cert)
			if (status.Errors != nil) != tt.wantErr {
				t.Fatalf("CheckCertStatus() error = %v, wantErr %v", status.Errors, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if status.IsValid != tt.wantValid {
				t.Errorf("CheckCertStatus().IsValid = %v, want %v", status.IsValid, tt.wantValid)
			}

			if tt.wantOCSPError && !errorContains(status.Errors, "OCSP") {
				t.Errorf("Expected OCSP error in status.Errors, got %v", status.Errors)
			}

			if tt.wantCRLError && !errorContains(status.Errors, "CRL") {
				t.Errorf("Expected CRL error in status.Errors, got %v", status.Errors)
			}
		})
	}
}

func errorContains(errors []string, substr string) bool {
	if errors == nil {
		return false
	}

	return slices.Contains(errors, substr)
}
