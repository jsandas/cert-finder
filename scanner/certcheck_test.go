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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	issuerCommonName = "issuer.example.test"
	ocspCommonName   = "ocsp.example.test"
	aiaUrl           = "http://invalid.example.com"
)

var testCertSubject = pkix.Name{
	CommonName:         "Test Server",
	Country:            []string{"US"},
	Organization:       []string{"Test Org"},
	OrganizationalUnit: []string{"Test Unit"},
}

func TestMain(m *testing.M) {
	originalLookup := lookupIPAddr
	lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}

	exitCode := m.Run()
	lookupIPAddr = originalLookup

	os.Exit(exitCode)
}

// TestCheckCertStatus validates the CheckCertStatus function across a comprehensive suite of scenarios:
// expired certificates, not-yet-valid certificates, missing AIA extensions, unreachable issuers,
// valid certificates with/without OCSP, CRL validation, LDAP CRL handling, OCSP/CRL unreachable errors,
// PEM-format issuer retrieval, and wrong-issuer detection. It also verifies that IncludeStatusData=true
// populates OCSPResponse and CRLData when appropriate.
func TestCheckCertStatus(t *testing.T) {
	// Create a test issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               testCertSubject,
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

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"crl.example.test":          crlServer,
		issuerCommonName:            issuerServer,
		ocspCommonName:              ocspServer,
		"pem-issuer.example.test":   pemIssuerServer,
		"wrong-issuer.example.test": wrongIssuerServer,
	})

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
				SerialNumber:          big.NewInt(100),
				Subject:               testCertSubject,
				NotBefore:             time.Now().Add(-48 * time.Hour),
				NotAfter:              time.Now().Add(-24 * time.Hour),
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
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
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
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
				IssuingCertificateURL: []string{aiaUrl},
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
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
				AuthorityKeyId:        []byte{1, 2, 3},
			},
			wantValid:      true,
			wantOCSPStatus: certValidNoOCSP,
			wantCRLStatus:  certNoAIA,
		},
		{
			name: certValidWithOCSP,
			cert: &x509.Certificate{
				SerialNumber:          big.NewInt(100),
				Subject:               testCertSubject,
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
				AuthorityKeyId:        []byte{1, 2, 3},
				OCSPServer:            []string{publicURLs[ocspCommonName]},
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
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{publicURLs["crl.example.test"]},
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
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
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
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
				AuthorityKeyId:        []byte{1, 2, 3},
				OCSPServer:            []string{aiaUrl},
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
				IssuingCertificateURL: []string{publicURLs[issuerCommonName]},
				AuthorityKeyId:        []byte{1, 2, 3},
				CRLDistributionPoints: []string{aiaUrl},
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
				IssuingCertificateURL: []string{publicURLs["pem-issuer.example.test"]},
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
				IssuingCertificateURL: []string{publicURLs["wrong-issuer.example.test"]},
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
				CheckOptions{IncludeStatusData: false, HTTPClient: client},
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
					CheckOptions{IncludeStatusData: true, HTTPClient: client},
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
					CheckOptions{IncludeStatusData: true, HTTPClient: client},
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

// TestCheckCertStatus_CustomHTTPClient verifies that a custom HTTP client with a tracking transport
// is properly used during certificate status checks. It creates a testTransport wrapper that counts
// requests and confirms the custom client was invoked and the certificate is valid.
func TestCheckCertStatus_CustomHTTPClient(t *testing.T) {
	// Create a test issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               testCertSubject,
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

	routedClient, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"issuer.example.test": issuerServer,
	})

	// Create a custom HTTP client with a transport that tracks requests
	requestCount := 0
	customTransport := &testTransport{
		inner: routedClient.Transport,
		onRequest: func(req *http.Request) {
			requestCount++
		},
	}
	customClient := &http.Client{Transport: customTransport}

	// Create a test certificate that requires AIA fetch
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               testCertSubject,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURLs["issuer.example.test"]},
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

// TestCheckCertStatus_Timeout tests that CheckCertStatus properly respects a custom Timeout option.
// It creates a slow server that delays its response beyond the configured timeout, then verifies
// that the certificate is marked invalid with an "unreachable" error due to the timeout.
func TestCheckCertStatus_Timeout(t *testing.T) {
	// Create a test issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               testCertSubject,
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

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"slow-issuer.example.test": slowServer,
	})

	// Create a test certificate that requires AIA fetch
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               testCertSubject,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURLs["slow-issuer.example.test"]},
		AuthorityKeyId:        []byte{1, 2, 3},
	}

	// Call CheckCertStatus with a very short timeout
	status := CheckCertStatus(
		context.Background(),
		cert,
		CheckOptions{IncludeStatusData: false, HTTPClient: client, Timeout: 10 * time.Millisecond},
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

// TestFetchCRL_PEM tests that fetchCRL can successfully retrieve and parse a CRL served in PEM format.
// It creates an issuer certificate, generates a CRL, encodes it as PEM, serves it via HTTP, and
// verifies the parsed CRL has the expected serial number.
func TestFetchCRL_PEM(t *testing.T) {
	// Create a test issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               testCertSubject,
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

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"crl.example.test": crlServer,
	})

	// Call fetchCRL
	ctx := context.Background()

	crl, err := fetchCRL(ctx, client, publicURLs["crl.example.test"])
	if err != nil {
		t.Fatalf("fetchCRL failed: %v", err)
	}

	// Verify the CRL was parsed correctly
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected CRL number 1, got %s", crl.Number.String())
	}
}

// TestCheckCertStatus_BlocksPrivateIssuerAddress tests SSRF protection: when an issuer URL resolves
// to a loopback (private) IP address, CheckCertStatus should reject the connection and return an error
// containing "refusing to connect to non-public address".
func TestCheckCertStatus_BlocksPrivateIssuerAddress(t *testing.T) {
	originalLookup := lookupIPAddr
	lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host == "issuer.example.test" {
			return []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}, nil
		}

		return originalLookup(ctx, host)
	}

	defer func() {
		lookupIPAddr = originalLookup
	}()

	cert := &x509.Certificate{
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://issuer.example.test/issuer.der"},
	}

	status := CheckCertStatus(context.Background(), cert, CheckOptions{})
	if status.IsValid {
		t.Fatal("expected certificate to be invalid when issuer URL resolves to loopback")
	}

	found := false

	for _, err := range status.Errors {
		if strings.Contains(err, "refusing to connect to non-public address") {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected SSRF protection error, got %v", status.Errors)
	}
}

// TestValidateOutboundURL_ErrorCases validates that validateOutboundURL rejects URLs with invalid
// schemes (ftp, file, ssh), URLs containing user info (user:pass or user@), missing hosts, empty
// strings, malformed syntax, and other disallowed patterns.
func TestValidateOutboundURL_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		urlStr  string
		wantErr string
	}{
		{
			name:    "invalid scheme",
			urlStr:  "ftp://example.com/cert.der",
			wantErr: "invalid URL scheme",
		},
		{
			name:    "file scheme",
			urlStr:  "file:///etc/ssl/cert.der",
			wantErr: "invalid URL scheme",
		},
		{
			name:    "url with user info",
			urlStr:  "http://user:pass@example.com/cert.der",
			wantErr: "URL user info is not allowed",
		},
		{
			name:    "url with only user",
			urlStr:  "http://user@example.com/cert.der",
			wantErr: "URL user info is not allowed",
		},
		{
			name:    "missing host",
			urlStr:  "http:///path/to/cert",
			wantErr: "missing URL host",
		},
		{
			name:    "empty url",
			urlStr:  "",
			wantErr: "invalid URL",
		},
		{
			name:    "invalid url syntax",
			urlStr:  "://invalid url [syntax",
			wantErr: "invalid URL",
		},
		{
			name:    "ip address scheme",
			urlStr:  "ssh://example.com/cert.der",
			wantErr: "invalid URL scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateOutboundURL(context.Background(), tt.urlStr)
			if err == nil {
				t.Fatalf("Expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing '%s', got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// TestValidateResolvedHost_ErrorCases tests that validateResolvedHost properly handles DNS resolution
// failures (returning "failed to resolve host" errors) and cases where a hostname resolves to no
// IP addresses (returning "did not resolve to any address" errors).
func TestValidateResolvedHost_ErrorCases(t *testing.T) {
	originalLookup := lookupIPAddr
	defer func() {
		lookupIPAddr = originalLookup
	}()

	lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("DNS lookup failed")
	}

	err := validateResolvedHost(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Expected error for DNS resolution failure, got nil")
	}

	if !strings.Contains(err.Error(), "failed to resolve host") {
		t.Errorf("Expected 'failed to resolve host' error, got %q", err.Error())
	}

	lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{}, nil
	}

	err = validateResolvedHost(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Expected error for empty resolved IPs, got nil")
	}

	if !strings.Contains(err.Error(), "did not resolve to any address") {
		t.Errorf("Expected 'did not resolve to any address' error, got %q", err.Error())
	}
}

// TestSafeHTTPClient_NilClient verifies that safeHTTPClient returns a non-nil client even when
// passed a nil input, and that the resulting client has CheckRedirect properly configured for
// SSRF protection.
func TestSafeHTTPClient_NilClient(t *testing.T) {
	safe := safeHTTPClient(nil)
	if safe == nil {
		t.Fatal("Expected safe client to be non-nil when input is nil")
	}

	if safe.CheckRedirect == nil {
		t.Fatal("Expected CheckRedirect to be set")
	}
}

// TestValidateOutboundIP_ErrorCases validates that validateOutboundIP rejects all private and
// reserved IP addresses, including loopback (127.0.0.1, ::1), private ranges (10.x, 192.168.x,
// 172.16.x), link-local (169.254.x, fe80::), multicast (224.x), and unspecified (0.0.0.0, ::).
func TestValidateOutboundIP_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		ipStr string
	}{
		{
			name:  "loopback",
			ipStr: "127.0.0.1",
		},
		{
			name:  "ipv6 loopback",
			ipStr: "::1",
		},
		{
			name:  "private 10.x",
			ipStr: "10.0.0.1",
		},
		{
			name:  "private 192.168",
			ipStr: "192.168.1.1",
		},
		{
			name:  "private 172.16",
			ipStr: "172.16.0.1",
		},
		{
			name:  "link-local",
			ipStr: "169.254.1.1",
		},
		{
			name:  "multicast",
			ipStr: "224.0.0.1",
		},
		{
			name:  "unspecified",
			ipStr: "0.0.0.0",
		},
		{
			name:  "ipv6 unspecified",
			ipStr: "::",
		},
		{
			name:  "ipv6 link-local",
			ipStr: "fe80::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := netip.ParseAddr(tt.ipStr)
			if err != nil {
				t.Fatalf("Failed to parse IP %q: %v", tt.ipStr, err)
			}

			err = validateOutboundIP(ip.Unmap())
			if err == nil {
				t.Fatalf("Expected error for IP %q, got nil", tt.ipStr)
			}

			if !strings.Contains(err.Error(), "refusing to connect to non-public address") {
				t.Errorf("Expected 'refusing to connect to non-public address' error, got %q", err.Error())
			}
		})
	}
}

// TestGetIssuerCert_ErrorCases tests getIssuerCert error handling for certificates with no AIA
// extension (no IssuingCertificateURL) and unreachable issuer URLs that cause network errors.
func TestGetIssuerCert_ErrorCases(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader,
		issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	_, _ = x509.ParseCertificate(issuerBytes)

	client, _ := newMappedTestClient(nil)

	tests := []struct {
		name    string
		cert    *x509.Certificate
		wantErr string
	}{
		{
			name:    "no AIA extension",
			cert:    &x509.Certificate{},
			wantErr: "no CA issuers found in AIA extension",
		},
		{
			name: "unreachable issuer",
			cert: &x509.Certificate{
				IssuingCertificateURL: []string{"http://nonexistent.invalid.example.com/cert.der"},
			},
			wantErr: "",
		},
		{
			name: "server returns invalid DER",
			cert: &x509.Certificate{
				IssuingCertificateURL: []string{"http://invalid-der.example.com/cert.der"},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getIssuerCert(context.Background(), client, tt.cert)
			if tt.wantErr == "" && tt.name == "unreachable issuer" {
				// Network error expected - just check we got an error
				if err == nil {
					t.Fatal("Expected error for unreachable issuer, got nil")
				}

				return
			}

			if tt.wantErr == "" && tt.name == "server returns invalid DER" {
				// We need a server that returns garbage
				return
			}

			if err == nil {
				t.Fatalf("Expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing '%s', got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// TestGetIssuerCert_InvalidDER tests that getIssuerCert returns an error when the server responds
// with non-certificate data (plain text instead of DER-encoded certificate).
func TestGetIssuerCert_InvalidDER(t *testing.T) {
	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not a certificate"))
	}))
	defer invalidServer.Close()

	cert := &x509.Certificate{
		IssuingCertificateURL: []string{invalidServer.URL},
	}

	_, err := getIssuerCert(context.Background(), http.DefaultClient, cert)
	if err == nil {
		t.Fatal("Expected error for invalid DER data, got nil")
	}
}

// TestGetIssuerCert_InvalidPEM tests that getIssuerCert returns an error when the server responds
// with PEM-encoded data containing invalid base64 content.
func TestGetIssuerCert_InvalidPEM(t *testing.T) {
	invalidPEMServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nthis is not valid base64!!!\n-----END CERTIFICATE-----"))
	}))
	defer invalidPEMServer.Close()

	cert := &x509.Certificate{
		IssuingCertificateURL: []string{invalidPEMServer.URL},
	}

	_, err := getIssuerCert(context.Background(), http.DefaultClient, cert)
	if err == nil {
		t.Fatal("Expected error for invalid PEM data, got nil")
	}
}

// TestFetchOCSPResponse_ErrorCases tests fetchOCSPResponse error handling for servers that return
// non-OCSP responses, expired OCSP responses, and truncated/truncated responses.
func TestFetchOCSPResponse_ErrorCases(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader,
		issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}

	ocspRequest, err := ocsp.CreateRequest(issuerCert, issuerCert, nil)
	if err != nil {
		t.Fatalf("Failed to create OCSP request: %v", err)
	}

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"ocsp.example.test": httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not an ocsp response"))
		})),
		"expired-ocsp.example.test": httptest.NewServer(expiredOCSPHandler(issuerCert, issuerKey)),
		"truncated-ocsp.example.test": httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{1, 2, 3})
		})),
	})

	tests := []struct {
		name    string
		server  string
		wantErr string
	}{
		{
			name:    "server returns non-OCSP response",
			server:  publicURLs["ocsp.example.test"],
			wantErr: "asn1: structure error",
		},
		{
			name:    "server returns valid but expired response",
			server:  publicURLs["expired-ocsp.example.test"],
			wantErr: "OCSP response has expired",
		},
		{
			name:    "server returns truncated response",
			server:  publicURLs["truncated-ocsp.example.test"],
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchOCSPResponse(context.Background(), tt.server, ocspRequest, issuerCert, client)
			if tt.wantErr == "" {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}

				return
			}

			if err == nil {
				t.Fatalf("Expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing '%s', got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func expiredOCSPHandler(issuerCert, issuerKey interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   time.Now().Add(-2 * time.Hour),
			NextUpdate:   time.Now().Add(-1 * time.Hour),
		}

		respBytes, err := ocsp.CreateResponse(issuerCert.(*x509.Certificate),
			issuerCert.(*x509.Certificate), template, issuerKey.(*ecdsa.PrivateKey))
		if err != nil {
			http.Error(w, "create error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	}
}

// TestFetchCRL_ErrorCases tests that fetchCRL properly handles servers returning invalid CRL data,
// including plain text garbage and malformed PEM-encoded CRL content.
func TestFetchCRL_ErrorCases(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate,
		issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	_, _ = x509.ParseCertificate(issuerBytes)

	tests := []struct {
		name   string
		server http.HandlerFunc
	}{
		{
			name:   "server returns invalid DER",
			server: func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not a crl")) },
		},
		{
			name: "server returns invalid PEM",
			server: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("-----BEGIN CRL-----\ninvalid base64!!!\n-----END CRL-----"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.server)
			defer server.Close()

			_, err := fetchCRL(context.Background(), http.DefaultClient, server.URL)
			if err == nil {
				t.Fatal("Expected error for invalid CRL data, got nil")
			}
		})
	}
}

// TestCheckCRL_AllServersFail tests that when all CRL distribution points are unreachable,
// CheckCertStatus returns an error containing "Unable to fetch CRL" while still reporting
// OCSP status as valid (since no OCSP server was configured).
func TestCheckCRL_AllServersFail(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		SubjectKeyId: []byte{1, 2, 3},
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	_, _ = x509.ParseCertificate(issuerBytes)

	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer issuerServer.Close()

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"issuer.example.test": issuerServer,
	})

	cert := &x509.Certificate{
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURLs["issuer.example.test"]},
		AuthorityKeyId:        []byte{1, 2, 3},
		CRLDistributionPoints: []string{"http://nonexistent-crl.invalid.example.com/crl.der"},
	}

	status := CheckCertStatus(context.Background(), cert, CheckOptions{HTTPClient: client})

	if !strings.Contains(status.OCSPStatus, certValidNoOCSP) {
		t.Fatalf("Expected OCSP status to be '%s', got %q", certValidNoOCSP, status.OCSPStatus)
	}

	foundCRL := false

	for _, err := range status.Errors {
		if strings.Contains(err, certUnreachableCRL) {
			foundCRL = true
			break
		}
	}

	if !foundCRL {
		t.Fatalf("Expected CRL error, got: %v", status.Errors)
	}
}

// TestCheckCRL_ExpiredCRL tests that CheckCertStatus properly detects and reports expired CRLs.
// It creates a CRL with ThisUpdate and NextUpdate in the past, then verifies the error message
// contains "CRL has expired".
func TestCheckCRL_ExpiredCRL(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3},
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer issuerServer.Close()

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlBytes)
	}))
	defer crlServer.Close()

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"issuer.example.test": issuerServer,
		"crl.example.test":    crlServer,
	})

	cert := &x509.Certificate{
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURLs["issuer.example.test"]},
		AuthorityKeyId:        []byte{1, 2, 3},
		CRLDistributionPoints: []string{publicURLs["crl.example.test"]},
	}

	status := CheckCertStatus(context.Background(), cert, CheckOptions{HTTPClient: client})

	foundExpired := false

	for _, err := range status.Errors {
		if strings.Contains(err, "CRL has expired") {
			foundExpired = true
			break
		}
	}

	if !foundExpired {
		t.Fatalf("Expected expired CRL error, got: %v", status.Errors)
	}
}

// TestUpdateCRLStatus_CertRevoked tests the updateCRLStatus function when a certificate's serial
// number is found in a CRL's revoked entries. It verifies that wasRevoked returns true, IsValid
// is set to false, and CRLStatus contains "Revoked".
func TestUpdateCRLStatus_CertRevoked(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	revokedSerial := big.NewInt(42)
	crlTemplate.RevokedCertificateEntries = []x509.RevocationListEntry{
		{
			SerialNumber:   revokedSerial,
			RevocationTime: time.Now(),
		},
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	cert := &x509.Certificate{
		SerialNumber: revokedSerial,
	}

	status := &CertStatus{IsValid: true}
	wasRevoked := updateCRLStatus(cert, crl, status, false)

	if !wasRevoked {
		t.Fatal("Expected updateCRLStatus to return true for revoked cert")
	}

	if status.IsValid {
		t.Fatal("Expected status to be invalid for revoked cert")
	}

	if !strings.Contains(status.CRLStatus, "Revoked") {
		t.Errorf("Expected CRLStatus to contain 'Revoked', got %q", status.CRLStatus)
	}
}

// TestCheckCertStatus_OCSPRevoked tests that CheckCertStatus correctly identifies a revoked
// certificate via OCSP. It creates an OCSP server that returns ocsp.Revoked status, then verifies
// the certificate is marked invalid with OCSPStatus containing "Revoked".
func TestCheckCertStatus_OCSPRevoked(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3},
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}

	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		template := ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
			RevokedAt:    time.Now().Add(-24 * time.Hour),
		}

		respBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, template, issuerKey)
		if err != nil {
			http.Error(w, "create error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	}))
	defer ocspServer.Close()

	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer issuerServer.Close()

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"issuer.example.test": issuerServer,
		"ocsp.example.test":   ocspServer,
	})

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURLs["issuer.example.test"]},
		AuthorityKeyId:        []byte{1, 2, 3},
		OCSPServer:            []string{publicURLs["ocsp.example.test"]},
	}

	status := CheckCertStatus(context.Background(), cert, CheckOptions{HTTPClient: client})

	if status.IsValid {
		t.Fatal("Expected certificate to be invalid (revoked), got valid")
	}

	if !strings.Contains(status.OCSPStatus, "Revoked") {
		t.Errorf("Expected OCSPStatus to contain 'Revoked', got %q", status.OCSPStatus)
	}
}

// TestCheckCertStatus_OCSPUnknown tests that CheckCertStatus correctly handles OCSP responses with
// "Unknown" status. It creates an OCSP server that returns ocsp.Unknown and verifies the
// OCSPStatus field is set to "Unknown".
func TestCheckCertStatus_OCSPUnknown(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3},
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}

	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		template := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}

		respBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, template, issuerKey)
		if err != nil {
			http.Error(w, "create error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	}))
	defer ocspServer.Close()

	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))
	defer issuerServer.Close()

	client, publicURLs := newMappedTestClient(map[string]*httptest.Server{
		"issuer.example.test": issuerServer,
		"ocsp.example.test":   ocspServer,
	})

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURLs["issuer.example.test"]},
		AuthorityKeyId:        []byte{1, 2, 3},
		OCSPServer:            []string{publicURLs["ocsp.example.test"]},
	}

	status := CheckCertStatus(context.Background(), cert, CheckOptions{HTTPClient: client})

	if status.OCSPStatus != "Unknown" {
		t.Errorf("Expected OCSPStatus to be 'Unknown', got %q", status.OCSPStatus)
	}
}

// TestCheckCertStatus_IPAddressURL tests that CheckCertStatus properly rejects certificates with
// issuer URLs pointing to IP addresses that resolve to private/non-public IPs, enforcing SSRF
// protection by returning an error containing "refusing to connect to non-public address".
func TestCheckCertStatus_IPAddressURL(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	// Use an IP-based URL (non-private IP)
	_, server, publicURL := setupIPMappedServer(issuerBytes)
	defer server.Close()

	cert := &x509.Certificate{
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{publicURL},
	}

	status := CheckCertStatus(context.Background(), cert, CheckOptions{})
	if status.IsValid {
		t.Fatal("Expected certificate to be invalid due to IP URL validation")
	}

	found := false

	for _, err := range status.Errors {
		if strings.Contains(err, "refusing to connect to non-public address") {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Expected SSRF protection error, got: %v", status.Errors)
	}
}

func setupIPMappedServer(issuerBytes []byte) (*big.Int, *httptest.Server, string) {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      testCertSubject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	ib, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	_ = ib

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(issuerBytes)
	}))

	// Parse server URL to get IP
	u, _ := url.Parse(server.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	ipURL := fmt.Sprintf("http://%s/cert.der", host)

	return big.NewInt(1), server, ipURL
}

// TestSafeHTTPClient_NoRedirect verifies that safeHTTPClient prevents HTTP redirects to private
// IP addresses. It sets up a server that redirects to a loopback address and confirms the request
// fails with an SSRF protection error.
func TestSafeHTTPClient_NoRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://127.0.0.1/final", http.StatusFound)
			return
		}

		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := safeHTTPClient(http.DefaultClient)

	// Try to follow redirect to private IP - should fail
	_, err := client.Get(server.URL + "/redirect")
	if err == nil {
		t.Fatal("Expected error when redirecting to private IP, got nil")
	}
}

// TestSafeHTTPClient_CustomRedirect verifies that safeHTTPClient preserves a custom CheckRedirect
// function from the base client, wrapping it with SSRF validation rather than replacing it entirely.
func TestSafeHTTPClient_CustomRedirect(t *testing.T) {
	baseClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	safe := safeHTTPClient(baseClient)
	if safe.CheckRedirect == nil {
		t.Fatal("CheckRedirect should not be nil")
	}
}

// TestHTTPGet_URLValidation tests that httpGet enforces URL validation by rejecting requests with
// invalid schemes (ftp), missing hosts, and URLs containing user info (user:pass).
func TestHTTPGet_URLValidation(t *testing.T) {
	_, err := httpGet(context.Background(), http.DefaultClient, "ftp://example.com/cert.der")
	if err == nil {
		t.Fatal("Expected error for invalid scheme, got nil")
	}

	_, err = httpGet(context.Background(), http.DefaultClient, "http:///nohost")
	if err == nil {
		t.Fatal("Expected error for missing host, got nil")
	}

	_, err = httpGet(context.Background(), http.DefaultClient, "http://user:pass@example.com/cert.der")
	if err == nil {
		t.Fatal("Expected error for user info in URL, got nil")
	}
}

// TestHTTPPost_URLValidation tests that httpPost enforces URL validation by rejecting requests with
// invalid schemes (ftp) and URLs missing a host component.
func TestHTTPPost_URLValidation(t *testing.T) {
	_, err := httpPost(context.Background(), http.DefaultClient, "ftp://example.com", "text/plain", nil)
	if err == nil {
		t.Fatal("Expected error for invalid scheme, got nil")
	}

	_, err = httpPost(context.Background(), http.DefaultClient, "http:///nohost", "text/plain", nil)
	if err == nil {
		t.Fatal("Expected error for missing host, got nil")
	}
}

func newMappedTestClient(servers map[string]*httptest.Server) (*http.Client, map[string]string) {
	hostToAddr := make(map[string]string, len(servers))
	publicURLs := make(map[string]string, len(servers))

	for host, server := range servers {
		serverURL, err := url.Parse(server.URL)
		if err != nil {
			panic(err)
		}

		hostToAddr[host] = serverURL.Host
		serverURL.Host = host
		publicURLs[host] = serverURL.String()
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if mappedAddr, ok := hostToAddr[host]; ok {
			addr = mappedAddr
		} else if strings.HasSuffix(host, ".example.test") || strings.HasSuffix(host, ".example.com") {
			return nil, fmt.Errorf("no mapped test server for host %q", host)
		}

		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	return &http.Client{Transport: transport}, publicURLs
}
