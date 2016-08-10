// Package ibmoidc provides code for using OpenID Connect to authenticate
// users via IBM w3id and IBM blueID.
package ibmoidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat/go-jwx/jwt"
	"golang.org/x/oauth2"
)

// IBMw3Endpoint is the Endpoint for IBM w3 ID authentication
var IBMw3idEndpoint = oauth2.Endpoint{
	AuthURL:  "https://w3id.tap.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/authorize",
	TokenURL: "https://w3id.tap.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/token",
}

// IBMw3idPublicKey is the rsa.PublicKey to use to verify the signature on
// an id_token value returned from IBMw3idEndpoint.TokenURL.
var IBMw3idPublicKey = pemToRSA(`
-----BEGIN CERTIFICATE-----
MIIE9TCCA92gAwIBAgIQWOR/OBcrWWF01H2dMB/axDANBgkqhkiG9w0BAQsFADBE
MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEdMBsGA1UEAxMU
R2VvVHJ1c3QgU1NMIENBIC0gRzMwHhcNMTUwNDA4MDAwMDAwWhcNMTcwNDA3MjM1
OTU5WjCBgjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMQ8wDQYDVQQH
FAZBcm1vbmsxNDAyBgNVBAoUK0ludGVybmF0aW9uYWwgQnVzaW5lc3MgTWFjaGlu
ZXMgQ29ycG9yYXRpb24xGTAXBgNVBAMUEHczaWQudGFwLmlibS5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbNMnE20rYCN1kfPp58DZ8cgBeK3yh
Z6aVsPx2iqY0GtxWpAQv5P5dD3mc3ZoQItPPHLOduvoqOXxdxzj6/qQlqUou9nUU
mYp6V6eKvpu9JOk3/yrzc1255OPCzHfvZHvZhQ7JNIeVxLJnhzhqDor3BXEgF/VH
2rTipRkC3T5R++jObjQ2vmE55YdYMP9O86RqMzau5LXgW3Pov0XY2MgMmUaEDoew
49BUsiZ9aiW+Tfil8PL8tCDUxULZoJTHirIOOhA+ZPtD0d8M8LYthR89GmRXyvOI
wOSaNPi+y5O4ID0lGzAqTjgKm64R25ZLwleMBISm6nWZY7+HsrEsPVSVAgMBAAGj
ggGiMIIBnjAbBgNVHREEFDASghB3M2lkLnRhcC5pYm0uY29tMAkGA1UdEwQCMAAw
DgYDVR0PAQH/BAQDAgWgMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9nbi5zeW1j
Yi5jb20vZ24uY3JsMIGdBgNVHSAEgZUwgZIwgY8GBmeBDAECAjCBhDA/BggrBgEF
BQcCARYzaHR0cHM6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291cmNlcy9yZXBvc2l0
b3J5L2xlZ2FsMEEGCCsGAQUFBwICMDUMM2h0dHBzOi8vd3d3Lmdlb3RydXN0LmNv
bS9yZXNvdXJjZXMvcmVwb3NpdG9yeS9sZWdhbDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAU0m/3lvSFP3I8MH0j2oV4m6N8WnwwVwYI
KwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vZ24uc3ltY2QuY29tMCYG
CCsGAQUFBzAChhpodHRwOi8vZ24uc3ltY2IuY29tL2duLmNydDANBgkqhkiG9w0B
AQsFAAOCAQEAPI8gm9gJThAQsKZy3Qr6MY51SRyY/HaHBK9Zq4kocReO+LI5kISc
d9JROIVHmnE/jbL/7z7tiSOkiQna43LrL7AUaCvDUPTCRqTClvfILXlpTHtiZ3Si
8fxV+Aac85NCVETv47X4K7G9err6ems0O2OIOU22SdHaWcB0Wtg0lmCFGnpdeKgA
AtFtuAk8BfGLVloXy9SGV09gwP8HbuUgUek4uMlA+ySXvMLrnEyl1KbWhm9b5N/Q
DSOIlfn+l1rSdDe6x6ss1yzYSb83G4F11i0vxUAncMSilNHJ3tKySwEoankiBhmS
Feny/MUth7ai8QV4J5//VfIh7lnVY0WWsg==
-----END CERTIFICATE-----
`)

// IBMblueIDEndpoint is the Endpoint for IBM blueID authentication
var IBMblueIDEndpoint = oauth2.Endpoint{
	AuthURL:  "https://idaas.iam.ibm.com/idaas/oidc/endpoint/default/authorize",
	TokenURL: "https://idaas.iam.ibm.com/idaas/oidc/endpoint/default/token",
}

// pemToRSA turns a PEM-encoded RSA public key into an rsa.PublicKey value.
// Intended for use on startup, so panics if any part of the decoding fails.
func pemToRSA(pemtxt string) *rsa.PublicKey {
	var pubkey *rsa.PublicKey
	block, _ := pem.Decode([]byte(pemtxt))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	pubkey = cert.PublicKey.(*rsa.PublicKey)
	return pubkey
}

func init() {
	// IBM w3 token endpoint HTTP Basic authentication doesn't work as of
	// 2016-06-03.
	oauth2.RegisterBrokenAuthHeaderProvider(IBMw3idEndpoint.TokenURL)
}

// UnmarshalJSON turns a JSON payload from a JWS token into a set of claims,
// and handles remapping IBM-specific private claims to standard ones:
//
// lastName     → family_name
// firstName    → given_name
// cn           → name
// dn           → sub
// emailAddress → email
//
// The original emailAddress claim is left intact, as are the dn and realmName
// claims. The others are removed after remapping.
//
func UnmarshalJSON(jsondata []byte) (*jwt.ClaimSet, error) {
	cset := jwt.NewClaimSet()
	err := cset.UnmarshalJSON(jsondata)
	if err != nil {
		return cset, err
	}
	// IBM returns either an array or a string as e-mail address
	email := cset.Get("emailAddress")
	switch et := email.(type) {
	case string:
		cset.Set("email", et)
	case []interface{}:
		cset.Set("email", et[0].(string))
	default:
		return cset, fmt.Errorf("emailAddress claim of unexpected type")
	}
	// Remap some other fields
	remap := map[string]string{
		"lastName":  "family_name",
		"firstName": "given_name",
		"cn":        "name",
	}
	for kf, kt := range remap {
		v := cset.Get(kf)
		cset.Set(kt, v)
		delete(cset.PrivateClaims, kf)
	}
	return cset, nil
}

// Decode unpacks an id_token payload, as returned from the token endpoint,
// from its raw base64-encoded value.
func Decode(payload []byte) (*jwt.ClaimSet, error) {
	s := strings.Split(string(payload), ".")
	if len(s) < 2 {
		return nil, errors.New("invalid id_token payload: not a triple")
	}
	jpld, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, fmt.Errorf("can't decode id_token: %s", err)
	}
	return UnmarshalJSON(jpld)
}
