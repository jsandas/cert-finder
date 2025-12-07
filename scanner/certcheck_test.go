package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

	// Create PEM-encoded issuer for testing PEM parsing
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerBytes})
	pemIssuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(pemBytes)
	}))

	defer pemIssuerServer.Close()

	// Create a wrong issuer certificate for testing verification failure
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate wrong issuer key: %v", err)
	}

	wrongTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Wrong Issuer CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{4, 5, 6}, // Different from issuer's {1,2,3}
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	wrongBytes, err := x509.CreateCertificate(rand.Reader, wrongTemplate, wrongTemplate, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatalf("Failed to create wrong issuer certificate: %v", err)
	}

	wrongIssuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(wrongBytes)
	}))
	defer wrongIssuerServer.Close()

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
			wantValid:     false,
			wantErrors:    []string{fmt.Sprintf("%s: no CA issuers found in AIA extension", certUnreachable)},
			wantCRLStatus: certNoAIA,
		},
		{
			name: certUnreachable,
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://invalid.example.com"},
			},
			wantValid:     false,
			wantErrors:    []string{certUnreachable},
			wantCRLStatus: certNoAIA,
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
		{
			name: "Issuer certificate in PEM format",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{pemIssuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
			},
			wantValid:      true,
			wantOCSPStatus: certValidNoOCSP,
			wantCRLStatus:  certNoAIA,
		},
		{
			name: "Retrieved certificate is not the issuer",
			cert: &x509.Certificate{
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{wrongIssuerServer.URL},
				AuthorityKeyId:        []byte{1, 2, 3},
			},
			wantValid:      false,
			wantErrors:     []string{fmt.Sprintf("%s: retrieved certificate is not the issuer", certUnreachable)},
			wantOCSPStatus: "",
			wantCRLStatus:  certNoAIA,
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

func TestCheckCertStatus_CustomHTTPClient(t *testing.T) {
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
		SubjectKeyId:          []byte{1, 2, 3},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate,
		issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer certificate: %v", err)
	}

	// Setup mock issuer server
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer issuerServer.Close()

	// Create a custom HTTP client with a transport that tracks requests
	requestCount := 0
	customTransport := &testTransport{
		inner: http.DefaultTransport,
		onRequest: func(req *http.Request) {
			requestCount++
		},
	}
	customClient := &http.Client{Transport: customTransport}

	// Create a test certificate that requires AIA fetch
	cert := &x509.Certificate{
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
	}

	// Call CheckCertStatus with custom client
	status := CheckCertStatus(
		context.Background(),
		cert,
		CheckOptions{IncludeStatusData: false, HTTPClient: customClient},
	)

	// Verify the custom client was used (request count should be > 0)
	if requestCount == 0 {
		t.Errorf("Custom HTTP client was not used; expected at least 1 request")
	}

	// Verify the status is valid (since we provided the issuer)
	if !status.IsValid {
		t.Errorf("Expected certificate to be valid, but got errors: %v", status.Errors)
	}
}

func TestCheckCertStatus_Timeout(t *testing.T) {
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
		SubjectKeyId:          []byte{1, 2, 3},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate,
		issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer certificate: %v", err)
	}

	// Setup a slow server that delays response
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Delay longer than our timeout
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer slowServer.Close()

	// Create a test certificate that requires AIA fetch
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:         "Test Server",
			Country:            []string{"US"},
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{slowServer.URL},
		AuthorityKeyId:        []byte{1, 2, 3},
	}

	// Call CheckCertStatus with a very short timeout
	status := CheckCertStatus(
		context.Background(),
		cert,
		CheckOptions{IncludeStatusData: false, HTTPClient: http.DefaultClient, Timeout: 10 * time.Millisecond},
	)

	// Verify that the call timed out and certificate is invalid due to unreachable issuer
	if status.IsValid {
		t.Errorf("Expected certificate to be invalid due to timeout, but it was valid")
	}

	// Check that we have an error related to unreachable issuer
	foundUnreachable := false

	for _, err := range status.Errors {
		if strings.Contains(err, certUnreachable) {
			foundUnreachable = true
			break
		}
	}

	if !foundUnreachable {
		t.Errorf("Expected error containing '%s' due to timeout, but got: %v", certUnreachable, status.Errors)
	}
}

// testTransport is a custom RoundTripper that tracks requests.
type testTransport struct {
	inner     http.RoundTripper
	onRequest func(*http.Request)
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.onRequest != nil {
		t.onRequest(req)
	}

	return t.inner.RoundTrip(req)
}

func TestFetchCRL_PEM(t *testing.T) {
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
		SubjectKeyId:          []byte{1, 2, 3},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Self-sign the issuer certificate
	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate,
		issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer certificate: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer certificate: %v", err)
	}

	// Create CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	// Encode CRL in PEM format
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	// Create HTTP server that serves the PEM-encoded CRL
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlPEM)
	}))
	defer crlServer.Close()

	// Call fetchCRL
	ctx := context.Background()
	client := &http.Client{}

	crl, err := fetchCRL(ctx, client, crlServer.URL)
	if err != nil {
		t.Fatalf("fetchCRL failed: %v", err)
	}

	// Verify the CRL was parsed correctly
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected CRL number 1, got %s", crl.Number.String())
	}
}
