package scanner

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Additional certificate validation error constants.
const (
	ocspExpired = "OCSP response has expired"
	crlExpired  = "CRL has expired"
)

// CertStatus represents the validity status of a certificate.
type CertStatus struct {
	IsValid      bool
	OCSPStatus   string
	CRLStatus    string
	LastChecked  time.Time
	Errors       []string
	OCSPResponse *ocsp.Response
	CRLData      *x509.RevocationList // List of revoked certificate serial numbers
}

// CheckOptions holds optional parameters for status checks.
type CheckOptions struct {
	IncludeStatusData bool
	HTTPClient        *http.Client
	Timeout           time.Duration
}

// httpGet performs a GET request with URL validation using provided context and client.
func httpGet(ctx context.Context, client *http.Client, urlStr string) (*http.Response, error) {
	// Parse and validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %v", urlStr, err)
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme %q", parsedURL.Scheme)
	}

	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	return client.Do(req)
}

// httpPost performs a POST request with URL validation using provided context and client.
func httpPost(
	ctx context.Context,
	client *http.Client,
	urlStr string,
	contentType string,
	body io.Reader,
) (*http.Response, error) {
	// Parse and validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %v", urlStr, err)
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme %q", parsedURL.Scheme)
	}

	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", contentType)

	return client.Do(req)
}

// getIssuerCert retrieves the issuer certificate from the AIA extension.
func getIssuerCert(ctx context.Context, client *http.Client, cert *x509.Certificate) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("no CA issuers found in AIA extension")
	}

	// Try each CA issuer URL
	var lastErr error

	for _, issuerURL := range cert.IssuingCertificateURL {
		resp, err := httpGet(ctx, client, issuerURL)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		// Try parsing as DER first
		issuer, err := x509.ParseCertificate(body)
		if err != nil {
			// Try PEM format if DER fails
			block, _ := pem.Decode(body)
			if block != nil {
				issuer, err = x509.ParseCertificate(block.Bytes)
			}

			if err != nil {
				lastErr = err
				continue
			}
		}

		// Verify this is actually the issuer
		if !bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) {
			lastErr = fmt.Errorf("retrieved certificate is not the issuer")
			continue
		}

		return issuer, nil
	}

	return nil, fmt.Errorf("%s : %v", certUnreachable, lastErr)
}

// CheckCertStatus checks Validity and both OCSP and CRL status of a certificate.
func CheckCertStatus(ctx context.Context, cert *x509.Certificate, opts CheckOptions) *CertStatus {
	status := &CertStatus{
		IsValid:     true,
		LastChecked: time.Now(),
	}

	// If a per-check timeout is provided in options, derive a child context
	if opts.Timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Check basic validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status.IsValid = false
		status.Errors = append(status.Errors, certNotYetValid)

		return status
	}

	if now.After(cert.NotAfter) {
		status.IsValid = false
		status.Errors = append(status.Errors, certExpired)

		return status
	}

	// Get issuer certificate
	issuerCert, err := getIssuerCert(ctx, opts.HTTPClient, cert)
	if err != nil {
		status.IsValid = false
		status.Errors = append(status.Errors, fmt.Sprintf("%s: %v", certUnreachable, err))

		return status
	}

	// Check OCSP status
	err = checkOCSP(ctx, cert, issuerCert, status, opts)
	if err != nil {
		status.Errors = append(status.Errors, fmt.Sprintf("%s : %v", certUnreachableOCSP, err))
	}

	// Check CRL status
	err = checkCRL(ctx, cert, status, opts)
	if err != nil {
		status.Errors = append(status.Errors, fmt.Sprintf("%s : %v", certUnreachableCRL, err))
	}

	return status
}

// processOCSPResponse updates the certificate status based on the OCSP response.
func processOCSPResponse(response *ocsp.Response, status *CertStatus, includeStatusData bool) {
	if includeStatusData {
		status.OCSPResponse = response
	}

	switch response.Status {
	case ocsp.Good:
		status.OCSPStatus = "Good"
	case ocsp.Revoked:
		status.OCSPStatus = fmt.Sprintf("Revoked at %s", response.RevokedAt)
		status.IsValid = false
	case ocsp.Unknown:
		status.OCSPStatus = "Unknown"
	}
}

// fetchOCSPResponse attempts to get an OCSP response from a server.
func fetchOCSPResponse(
	ctx context.Context,
	server string,
	request []byte,
	issuerCert *x509.Certificate,
	client *http.Client,
) (*ocsp.Response, error) {
	resp, err := httpPost(ctx, client, server, "application/ocsp-request", bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ocspResponse, err := ocsp.ParseResponse(body, issuerCert)
	if err != nil {
		return nil, err
	}

	if time.Now().After(ocspResponse.NextUpdate) {
		return nil, fmt.Errorf("%s", ocspExpired)
	}

	return ocspResponse, nil
}

func checkOCSP(ctx context.Context, cert *x509.Certificate, issuerCert *x509.Certificate, status *CertStatus,
	opts CheckOptions) error {
	// Skip if no OCSP servers defined
	if len(cert.OCSPServer) == 0 {
		status.OCSPStatus = certValidNoOCSP
		return nil
	}

	// Create OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuerCert, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %v", err)
	}

	// Try each OCSP server
	// Try each OCSP server
	var lastErr error

	for _, server := range cert.OCSPServer {
		response, err := fetchOCSPResponse(ctx, server, ocspRequest, issuerCert, opts.HTTPClient)
		if err != nil {
			lastErr = err
			continue
		}

		processOCSPResponse(response, status, opts.IncludeStatusData)

		return nil
	}

	return lastErr
}

// fetchCRL retrieves and parses a CRL from the given URL.
func fetchCRL(ctx context.Context, client *http.Client, crlDP string) (*x509.RevocationList, error) {
	resp, err := httpGet(ctx, client, crlDP)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try to parse as DER first
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		// Try PEM format if DER fails
		block, _ := pem.Decode(body)
		if block != nil {
			crl, err = x509.ParseRevocationList(block.Bytes)
		}

		if err != nil {
			return nil, err
		}
	}

	return crl, nil
}

// updateCRLStatus updates the status struct with CRL information and checks for revocation.
func updateCRLStatus(cert *x509.Certificate, crl *x509.RevocationList, status *CertStatus,
	includeStatusData bool) bool {
	// Only store the CRL data if includeStatusData is true
	if includeStatusData {
		status.CRLData = crl
	}

	// Check if serial number is in the CRL
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			status.CRLStatus = fmt.Sprintf("Revoked at %s", revokedCert.RevocationTime)
			status.IsValid = false

			return true
		}
	}

	status.CRLStatus = "Good"

	return false
}

func checkCRL(ctx context.Context, cert *x509.Certificate, status *CertStatus, opts CheckOptions) error {
	// Skip if no CRL endpoints defined
	if len(cert.CRLDistributionPoints) == 0 {
		status.CRLStatus = certNoAIA
		return nil
	}

	// Try each CRL distribution point
	var lastErr error

	for _, crlDP := range cert.CRLDistributionPoints {
		// Handle LDAP URLs
		if strings.HasPrefix(strings.ToLower(crlDP), "ldap:") {
			status.CRLStatus = certValidWithLDAP
			return nil
		}

		crl, err := fetchCRL(ctx, opts.HTTPClient, crlDP)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if the CRL is still valid
		if time.Now().After(crl.NextUpdate) {
			lastErr = fmt.Errorf("%s", crlExpired)
			continue
		}

		// Update status and check for revocation
		if updateCRLStatus(cert, crl, status, opts.IncludeStatusData) {
			return nil // Certificate was found in CRL
		}

		return nil // Certificate is good
	}

	return lastErr
}
