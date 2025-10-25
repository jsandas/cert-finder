package scanner

// Certificate validation error constants.
const (
	certExpired         = "Certificate is expired"
	certNotYetValid     = "Certificate is not yet valid"
	certNoAIA           = "Certificate has no AIA extension"
	certUnreachable     = "Unable to fetch issuer certificate"
	certValidNoOCSP     = "Certificate has no OCSP servers"
	certValidWithOCSP   = "Certificate OCSP is valid"
	certValidWithCRL    = "Certificate CRL is valid"
	certValidWithLDAP   = "Certificate has LDAP CRL"
	certUnreachableOCSP = "Unable to check OCSP status"
	certUnreachableCRL  = "Unable to fetch CRL"
)
