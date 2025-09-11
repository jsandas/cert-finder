package scanner

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// parseFile scans a file for TLS certificate information.
func parseFile(path string) ([]*x509.Certificate, error) {
	log.Printf("Starting scanner in file %s", path)

	var certificates []*x509.Certificate

	// parse certificates in a file
	// Read the file
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	if strings.HasPrefix(string(data), "-----BEGIN") {
		// PEM format
		certs, err := parsePEM(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificates: %v", err)
		}

		certificates = append(certificates, certs...)

		return certificates, nil
	}

	// Parse the certificates
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates: %v", err)
	}

	certificates = append(certificates, certs...)

	return certificates, nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	var block *pem.Block

	rest := data

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			certs = append(certs, cert)
		}
	}

	return certs, nil
}
