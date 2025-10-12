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

// CertStatus represents the validity status of a certificate.
type CertStatus struct {
	IsValid      bool
	OCSPStatus   string
	CRLStatus    string
	LastChecked  time.Time
	Error        error
	OCSPResponse *ocsp.Response
	// Storing just the relevant CRL information instead of the full response
	CRLNextUpdate time.Time
	CRLSerials    []string // List of revoked certificate serial numbers
}

// safeHTTPGet performs a GET request with URL validation and context.
func safeHTTPGet(urlStr string) (*http.Response, error) {
	// Parse and validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %v", urlStr, err)
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme %q", parsedURL.Scheme)
	}

	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	return http.DefaultClient.Do(req)
}

// safeHTTPPost performs a POST request with URL validation and context.
func safeHTTPPost(urlStr string, contentType string, body io.Reader) (*http.Response, error) {
	// Parse and validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %v", urlStr, err)
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme %q", parsedURL.Scheme)
	}

	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", contentType)

	return http.DefaultClient.Do(req)
}

// getIssuerCert retrieves the issuer certificate from the AIA extension.
func getIssuerCert(cert *x509.Certificate) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("no CA issuers found in AIA extension")
	}

	// Try each CA issuer URL
	var lastErr error

	for _, issuerURL := range cert.IssuingCertificateURL {
		resp, err := safeHTTPGet(issuerURL)
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

	return nil, fmt.Errorf("failed to retrieve issuer certificate: %v", lastErr)
}

// CheckCertStatus checks both OCSP and CRL status of a certificate.
func CheckCertStatus(cert *x509.Certificate) (*CertStatus, error) {
	status := &CertStatus{
		IsValid:     true,
		LastChecked: time.Now(),
	}

	// Get issuer certificate
	issuerCert, err := getIssuerCert(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer certificate: %v", err)
	}

	// Check basic validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status.IsValid = false
		status.Error = fmt.Errorf("certificate is not yet valid")

		return status, nil
	}

	if now.After(cert.NotAfter) {
		status.IsValid = false
		status.Error = fmt.Errorf("certificate has expired")

		return status, nil
	}

	// Check OCSP status
	err = checkOCSP(cert, issuerCert, status)
	if err != nil {
		status.Error = fmt.Errorf("OCSP check failed: %v", err)
	}

	// Check CRL status
	err = checkCRL(cert, status)
	if err != nil {
		if status.Error != nil {
			status.Error = fmt.Errorf("%v; CRL check failed: %v", status.Error, err)
		} else {
			status.Error = fmt.Errorf("CRL check failed: %v", err)
		}
	}

	return status, nil
}

func checkOCSP(cert *x509.Certificate, issuerCert *x509.Certificate, status *CertStatus) error {
	// Skip if no OCSP servers defined
	if len(cert.OCSPServer) == 0 {
		status.OCSPStatus = "No OCSP servers defined"
		return nil
	}

	// Create OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuerCert, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %v", err)
	}

	// Try each OCSP server
	var lastErr error

	for _, server := range cert.OCSPServer {
		resp, err := safeHTTPPost(server, "application/ocsp-request", bytes.NewReader(ocspRequest))
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

		ocspResponse, err := ocsp.ParseResponse(body, issuerCert)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if the OCSP response is still valid
		if time.Now().After(ocspResponse.NextUpdate) {
			lastErr = fmt.Errorf("OCSP response has expired")
			continue
		}

		status.OCSPResponse = ocspResponse
		switch ocspResponse.Status {
		case ocsp.Good:
			status.OCSPStatus = "Good"
		case ocsp.Revoked:
			status.OCSPStatus = fmt.Sprintf("Revoked at %s", ocspResponse.RevokedAt)
			status.IsValid = false
		case ocsp.Unknown:
			status.OCSPStatus = "Unknown"
		}

		return nil
	}

	return lastErr
}

// fetchCRL retrieves and parses a CRL from the given URL.
func fetchCRL(crlDP string) (*x509.RevocationList, error) {
	resp, err := safeHTTPGet(crlDP)
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
func updateCRLStatus(cert *x509.Certificate, crl *x509.RevocationList, status *CertStatus) bool {
	status.CRLNextUpdate = crl.NextUpdate
	status.CRLSerials = make([]string, 0, len(crl.RevokedCertificateEntries))

	for _, cert := range crl.RevokedCertificateEntries {
		status.CRLSerials = append(status.CRLSerials, cert.SerialNumber.String())
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

func checkCRL(cert *x509.Certificate, status *CertStatus) error {
	// Skip if no CRL endpoints defined
	if len(cert.CRLDistributionPoints) == 0 {
		status.CRLStatus = "No CRL distribution points defined"
		return nil
	}

	// Try each CRL distribution point
	var lastErr error

	for _, crlDP := range cert.CRLDistributionPoints {
		// Skip LDAP URLs
		if strings.HasPrefix(strings.ToLower(crlDP), "ldap:") {
			continue
		}

		crl, err := fetchCRL(crlDP)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if the CRL is still valid
		if time.Now().After(crl.NextUpdate) {
			lastErr = fmt.Errorf("CRL has expired")
			continue
		}

		// Update status and check for revocation
		if updateCRLStatus(cert, crl, status) {
			return nil // Certificate was found in CRL
		}

		return nil // Certificate is good
	}

	return lastErr
}
