package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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
			CommonName:         "Test Issuer CA",
			Country:            []string{"US"},
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
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
		// Create a proper OCSP response with full certificate details
		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(100),
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}

		respBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, template, issuerKey)
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
		name           string
		cert           *x509.Certificate
		wantValid      bool
		wantErrors     []string // Expected error messages
		wantOCSPStatus string
		wantCRLStatus  string
		wantCRLSerials []string // Expected serial numbers in CRL
	}{
		{
			name: certExpired,
			cert: &x509.Certificate{
				SerialNumber: big.NewInt(100),
				Subject: pkix.Name{
					CommonName:         "Test Server",
					Country:            []string{"US"},
					Organization:       []string{"Test Org"},
					OrganizationalUnit: []string{"Test Unit"},
				},
				NotBefore:             time.Now().Add(-48 * time.Hour),
				NotAfter:              time.Now().Add(-24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
			},
			wantValid:  false,
			wantErrors: []string{certExpired},
		},
		{
			name: certNotYetValid,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(24 * time.Hour),
				NotAfter:              time.Now().Add(48 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
			},
			wantValid:  false,
			wantErrors: []string{certNotYetValid},
		},
		{
			name: certNoAIA,
			cert: &x509.Certificate{
				NotBefore: time.Now().Add(-24 * time.Hour),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			wantValid:  false,
			wantErrors: []string{fmt.Sprintf("%s: no CA issuers found in AIA extension", certUnreachable)},
		},
		{
			name: certUnreachable,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://invalid.example.com"},
			},
			wantValid:  false,
			wantErrors: []string{certUnreachable},
		},
		{
			name: certValidNoOCSP,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
			},
			wantValid:      true,
			wantOCSPStatus: certValidNoOCSP,
			wantCRLStatus:  certNoAIA,
		},
		{
			name: certValidWithOCSP,
			cert: &x509.Certificate{
				SerialNumber: big.NewInt(100),
				Subject: pkix.Name{
					CommonName:         "Test Server",
					Country:            []string{"US"},
					Organization:       []string{"Test Org"},
					OrganizationalUnit: []string{"Test Unit"},
				},
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				OCSPServer:            []string{ocspServer.URL},
			},
			wantValid:      true,
			wantOCSPStatus: "Good",
			wantCRLStatus:  certNoAIA,
		},
		{
			name: certValidWithCRL,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{crlServer.URL},
			},
			wantValid:      true,
			wantOCSPStatus: certValidNoOCSP,
			wantCRLStatus:  "Good",
		},
		{
			name: certValidWithLDAP,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{"ldap://example.com/cn=crl"},
			},
			wantValid:      true,
			wantOCSPStatus: certValidNoOCSP,
			wantCRLStatus:  certValidWithLDAP,
		},
		{
			name: certUnreachableOCSP,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				OCSPServer:            []string{"http://invalid.example.com"},
			},
			wantValid: true,
			wantErrors: []string{
				"Unable to check OCSP status : failed to create OCSP request: asn1: structure error: empty integer",
			},
			wantOCSPStatus: "",
			wantCRLStatus:  certNoAIA,
		},
		{
			name: certUnreachableCRL,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{issuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{"http://invalid.example.com"},
			},
			wantValid:      true,
			wantErrors:     []string{certUnreachableCRL},
			wantOCSPStatus: certValidNoOCSP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := CheckCertStatus(
				context.Background(),
				tt.cert,
				CheckOptions{IncludeStatusData: false, HTTPClient: http.DefaultClient},
			)
			if status.IsValid != tt.wantValid {
				t.Errorf("CheckCertStatus().IsValid = %v, want %v", status.IsValid, tt.wantValid)
			}

			// Check for expected errors
			if len(tt.wantErrors) > 0 {
				if status.Errors == nil {
					t.Errorf("Expected errors %v but got nil", tt.wantErrors)
					return
				}

				for _, wantErr := range tt.wantErrors {
					found := false

					for _, gotErr := range status.Errors {
						if strings.Contains(gotErr, wantErr) {
							found = true
							break
						}
					}

					if !found {
						t.Errorf("Expected error containing '%s' not found in errors: %v", wantErr, status.Errors)
					}
				}
			} else if status.Errors != nil {
				t.Errorf("Expected no errors but got: %v", status.Errors)
			}

			// Check OCSP status
			if status.OCSPStatus != tt.wantOCSPStatus {
				t.Errorf("OCSP status = %v, want %v", status.OCSPStatus, tt.wantOCSPStatus)
			}

			// Check CRL status
			if status.CRLStatus != tt.wantCRLStatus {
				t.Errorf("CRL status = %v, want %v", status.CRLStatus, tt.wantCRLStatus)
			}

			// Additional CRL checks can be added here as needed

			// When includeStatusData is true, raw OCSP/CRL data should be populated where available.
			if len(tt.cert.OCSPServer) > 0 {
				statusWith := CheckCertStatus(
					context.Background(),
					tt.cert,
					CheckOptions{IncludeStatusData: true, HTTPClient: http.DefaultClient},
				)
				// Only expect OCSPResponse if the status indicates we received a response
				if statusWith.OCSPStatus != "" {
					if statusWith.OCSPResponse == nil {
						t.Errorf("Expected OCSPResponse to be populated when includeStatusData=true and OCSP status present for test %s",
							tt.name)
					}
				}
			}

			if len(tt.cert.CRLDistributionPoints) > 0 {
				statusWith := CheckCertStatus(
					context.Background(),
					tt.cert,
					CheckOptions{IncludeStatusData: true, HTTPClient: http.DefaultClient},
				)
				// Only expect CRLData when we actually fetched a CRL (status Good or Revoked)
				if strings.HasPrefix(statusWith.CRLStatus, "Good") || strings.HasPrefix(statusWith.CRLStatus, "Revoked") {
					if statusWith.CRLData == nil {
						t.Errorf("Expected CRLData to be populated when includeStatusData=true and CRL fetched for test %s",
							tt.name)
					}
				}
			}
		})
	}
}
