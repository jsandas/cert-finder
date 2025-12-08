package scanner

// Certificate validation error constants.
const (
	certExpired         = "Certificate is expired"
	certNotYetValid     = "Certificate is not yet valid"
	certNoAIA           = "Certificate has no AIA extension"
	certUnreachable     = "Unable to check certificate status"
	certValidNoOCSP     = "Certificate is valid, no OCSP server specified"
	certValidWithOCSP   = "Certificate OCSP is valid"
	certValidWithCRL    = "Certificate CRL is valid"
	certValidWithLDAP   = "Certificate is valid, CRL uses LDAP"
	certUnreachableOCSP = "Unable to check OCSP status"
	certUnreachableCRL  = "Unable to fetch CRL"
)
