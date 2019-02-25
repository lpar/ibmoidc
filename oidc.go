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

// IBMidEndpoint is the Endpoint for IBMid authentication.
var IBMidEndpoint = oauth2.Endpoint{
	AuthURL:  "https://idaas.iam.ibm.com/idaas/oidc/endpoint/default/authorize",
	TokenURL: "https://idaas.iam.ibm.com/idaas/oidc/endpoint/default/token",
}

var IBMidPublicKey = pemToRSA(`
-----BEGIN CERTIFICATE-----
MIIFijCCA3KgAwIBAgIIW9rTyXsPjfswDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UE
BhMCdXMxCzAJBgNVBAgTAnR4MRIwEAYDVQQHEwlzb2Z0bGF5ZXIxDDAKBgNVBAoT
A2libTENMAsGA1UECxMEaXNhbTEWMBQGA1UEAwwNKi5zc28uaWJtLmNvbTAeFw0x
NjA3MjYxODE3MjJaFw0yMTA3MjYxODE3MjJaMGMxCzAJBgNVBAYTAnVzMQswCQYD
VQQIEwJ0eDESMBAGA1UEBxMJc29mdGxheWVyMQwwCgYDVQQKEwNpYm0xDTALBgNV
BAsTBGlzYW0xFjAUBgNVBAMMDSouc3NvLmlibS5jb20wggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCzmGqNMH0mxwGfv1P/LlPeqseniWPC1j9Csy37nZnG
snUKoDT7nWUFhxgNDHWDODlsgE2hswSEfgqdYZyno5mQMGK7+jP3dnG0u+mpcQ8s
xQmpOOOzKmicWz1V5v8dCysVoBrVjV0DJnY/kdxcf4DJW5b5Jo/tdc0ILcJwechO
icOhndbkUdH6lQDVkmOcUY6fCDviZjUOjL33VfMvEZdhhEDhpjuANhcoq2vGUeg3
8ZuY8bK1MOmAcNcUNguWhi9NVjKEbfv/p8a0uet2bnfmkNkeqNtstRBa1XEAZLpO
LGxPqNL2v3SIRDNMavXKuecEYXMFFokga3IhmQzTRo9uktJbCl8B7THBvs+Ksm6S
hAlcgs0n7mhOiEMmcGMknl2Sc1VpRzb8gNMqq/C3YH8XC9xc0LyRXISN0ug6tQcs
YRoLUaN22vJU6Qu8kyADj1nVTNk1gq49l5mGGffhEbrghULIQLb0zLiapgX3Ma2a
4uhOmmKfH8HglOOfQemekuerXRNqZF0hMgyPagCga8w2LLiiMFUWQmS+qs7w55Cx
X+AIWjAOy6uddvgTF4JHdaPYFxP5/wynLC9OlP7+ijCJmW1enOVTdrn0nMdhE8sD
vjJCSWM03VQpxLQuXGoUQs3y+p9/22ft6VfYUOD8IXKPH+u6S0ZtaqqBdMXGHbKC
CwIDAQABo0IwQDAdBgNVHQ4EFgQU4dUZV6haEYrgZg0bKOaD2Hrgw7cwHwYDVR0j
BBgwFoAU4dUZV6haEYrgZg0bKOaD2Hrgw7cwDQYJKoZIhvcNAQEFBQADggIBAK9N
L+FdiQtsJKXjjRl7KiosJ+ez5fFqClzS23dSwXXWiXORTsIlnKfm5xetTPwnebRt
XbyfpdgeQ7x3mjhkfodtyj+of0OCskHLWCXzf3q/8XeGG6aOciQwrFL4KZEpBiQb
p3cMy0LmS+JOgchS37Y5WkXCwFGrHEIbb5X7qaOOmaMsQKoeztv+xPUVxfTb6n+i
2LGAXle6QXbmjhqE67EH2dLlAMVxFGDQIvXkz+mVQu78V10IPL2PTxx4y2ypXo/A
bIAlzhZmpUYvB/Qqs5nj8Hoxtspc9kluYfaSP2/o5QLyhFfxl3hfXyhxW8ngzkhQ
nXjDTqnXzes/ffcNw641gk8Nsb2l4KWicSVxPYcoaXDwn+L63cwCovn7pKiueoSK
gLldhFp/rjSqpYK8tZSGToeEgA1cl2Ia26phVKa5RnB27U0l4LLIZmzDoH9LOEyz
/VQAB3QQYQ7K3obcXraqcLeogf8vGYWChIqLL4nlqmeRrB0lDu/DZ7v5dgKrFws8
EYAmt7loO42lXpdqK6KwyRazDEQY2mCCEQiwGl3o7jri2zT6el6b1aO3gQEvGgf6
DDL5ZheWFybSPMYDdlqTMlrdq7PxhySnoqn0JjKWqJkN+1F0Kms/k6ZM8pqZX3Zm
1M/QwlvmNhXX3X0zORRmgusiV8MPDbiwkp82m335
-----END CERTIFICATE-----
`)

// IBMw3idStagingEndpoint is the endpoint for testing IBM w3ID authentication.
var IBMw3idStagingEndpoint = oauth2.Endpoint{
	AuthURL:  "https://w3id.alpha.sso.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/authorize",
	TokenURL: "https://w3id.alpha.sso.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/token",
}

var IBMw3idStagingPublicKey = pemToRSA(`
-----BEGIN CERTIFICATE-----
MIIFgDCCA2igAwIBAgIIL36iZKXHdl0wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UE
BhMCdXMxDDAKBgNVBAgTA2RhbDEMMAoGA1UEBxMDQ0lTMQwwCgYDVQQKEwNpYm0x
DTALBgNVBAsTBGlzYW0xFjAUBgNVBAMMDSouc3NvLmlibS5jb20wHhcNMTYwNzIw
MTI1NzU1WhcNMjEwNzIwMTI1NzU1WjBeMQswCQYDVQQGEwJ1czEMMAoGA1UECBMD
ZGFsMQwwCgYDVQQHEwNDSVMxDDAKBgNVBAoTA2libTENMAsGA1UECxMEaXNhbTEW
MBQGA1UEAwwNKi5zc28uaWJtLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAKHcfeeElNS9dkjqER+6S4QfuEv/Zi5FTjLf7coX902dU1JTUa6D8RBE
haxvqYTi7TLxMQArwJW6x1xCShFDlK7DWyqkNp1Vi7TLVY4eSy9S5QlvF8Z6mxpx
nNBCWpkWd3jBaZ/5HiW0luk/ZvqU82P1cVFrn+LiQQ834IDlyL/lSyaIoUd3+s2b
ssJt0ASOwHfjgy25Y39QEpzQqDPuW+2S4hGEYhRhwZM1YpS2cRxS0EiD34otP8FW
4CvRYh25e74ThdOhq8yTvNIjrxhSXIvCT2Yj9+bl9TbOZhvgaYP2ghEg7SfnHAbL
dz6dLkJ2jA+rhzUYA1jXNpNrLNFCCwlTxS//nYmU4qHrTAWtODgLvTuaiyBVyl2z
9w8TFYsRi/2eThFhxjXhDVf0rDz3jSmQHK4iBihuXIcOhcvRWJJPdUTdv1fqtt91
6112FKC+KucG5W6U/odOJ8oaqENtwYpJzPXcx+zHENkNSYbUXjwfl1nqZN2JwtVe
9QIdFxMJFTNJt8zOZIs7R8EjUNpfh8oVyC4KYModCcYSVwQfsswBYi14OZvXL9g2
kDCRLaNwj1FcmBEqIsiDGR//YsAwDq30tsmsfl7j/v1RhF0kkqkAfKZQjd74590L
1EzHNYALiXEK5UhXGjnjld8AxGKMrIgKqH9Gl2M7G8YhW1HUxRZNAgMBAAGjQjBA
MB0GA1UdDgQWBBQKI1QLqujSAAW7/R7PkkQ/krTAnjAfBgNVHSMEGDAWgBQKI1QL
qujSAAW7/R7PkkQ/krTAnjANBgkqhkiG9w0BAQUFAAOCAgEAlg9/cKQOvbfb+Oxk
uEbuJyVtPn77eDGaOqDa6HkBMq/0VpfsihvlkYHRZ8hCw7E4lx0ScA1sD9rM2vUi
D/cY903wP7cr5AlSkvVYpXX5jajYw6yV9SLiIpkz3I3O+TIL9YG5HTb7BFZ69ng2
F2fayJWO5DLrkrSnTpOY9A/taR4aAUoPt34sAnUD31oQyjCivl72KKD5NvGaFDoQ
aXcTZFAd+SV4Ix8vSJo7Ow9F5wVemu9Khy+mDC1Hyl+hx8fjHgnGpe/ZeklVnuaL
btM8MIZ+sbkAfxeYEhuTS79qM414uR9HWIDiC+R4kOacTzhpkAufsq5KqvNYEoc0
1wiIur6PJ6elbUCz/N6AAdQKl4SKi5dA925PdqPMBNDHnXbmBU2aibXxQGMxS/ZK
91IguNhyUeuFSITFY+OTFQeJOUioQ5meg2jiwAftL3WesQyQoL3TbjCR3KZ2nonG
KItT0KePrS+7Rf7VOIaPlCf0Z7YY4/eBaPtb1Kann2Zm3wfIz61Ae+5eVoy8l61f
SEwmEkPTcZDu1sFtu5wyqmXiNkEPyVb1iQnCMm87cZECGCHoNWERVTa7iStafSHX
vmnTitMiW+CK4xopp/Qjsiv8a7N8hdxcOWRYhcy/UbI4cnlsmtiWebp+5P/XmHyF
LE8MSbFAHuo8ezk3fOism6yVYHU=
-----END CERTIFICATE-----
`)

// IBMw3idEndpoint is the Endpoint for IBM w3ID authentication.
var IBMw3idEndpoint = oauth2.Endpoint{
	AuthURL:  "https://w3id.sso.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/authorize",
	TokenURL: "https://w3id.sso.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/token",
}

// IBMw3idPublicKey is the rsa.PublicKey to use to verify the signature on
// an id_token value returned from IBMw3idEndpoint.TokenURL.
var IBMw3idPublicKey = pemToRSA(`
-----BEGIN CERTIFICATE-----
MIIFijCCA3KgAwIBAgIIW9rTyXsPjfswDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UE
BhMCdXMxCzAJBgNVBAgTAnR4MRIwEAYDVQQHEwlzb2Z0bGF5ZXIxDDAKBgNVBAoT
A2libTENMAsGA1UECxMEaXNhbTEWMBQGA1UEAwwNKi5zc28uaWJtLmNvbTAeFw0x
NjA3MjYxODE3MjJaFw0yMTA3MjYxODE3MjJaMGMxCzAJBgNVBAYTAnVzMQswCQYD
VQQIEwJ0eDESMBAGA1UEBxMJc29mdGxheWVyMQwwCgYDVQQKEwNpYm0xDTALBgNV
BAsTBGlzYW0xFjAUBgNVBAMMDSouc3NvLmlibS5jb20wggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCzmGqNMH0mxwGfv1P/LlPeqseniWPC1j9Csy37nZnG
snUKoDT7nWUFhxgNDHWDODlsgE2hswSEfgqdYZyno5mQMGK7+jP3dnG0u+mpcQ8s
xQmpOOOzKmicWz1V5v8dCysVoBrVjV0DJnY/kdxcf4DJW5b5Jo/tdc0ILcJwechO
icOhndbkUdH6lQDVkmOcUY6fCDviZjUOjL33VfMvEZdhhEDhpjuANhcoq2vGUeg3
8ZuY8bK1MOmAcNcUNguWhi9NVjKEbfv/p8a0uet2bnfmkNkeqNtstRBa1XEAZLpO
LGxPqNL2v3SIRDNMavXKuecEYXMFFokga3IhmQzTRo9uktJbCl8B7THBvs+Ksm6S
hAlcgs0n7mhOiEMmcGMknl2Sc1VpRzb8gNMqq/C3YH8XC9xc0LyRXISN0ug6tQcs
YRoLUaN22vJU6Qu8kyADj1nVTNk1gq49l5mGGffhEbrghULIQLb0zLiapgX3Ma2a
4uhOmmKfH8HglOOfQemekuerXRNqZF0hMgyPagCga8w2LLiiMFUWQmS+qs7w55Cx
X+AIWjAOy6uddvgTF4JHdaPYFxP5/wynLC9OlP7+ijCJmW1enOVTdrn0nMdhE8sD
vjJCSWM03VQpxLQuXGoUQs3y+p9/22ft6VfYUOD8IXKPH+u6S0ZtaqqBdMXGHbKC
CwIDAQABo0IwQDAdBgNVHQ4EFgQU4dUZV6haEYrgZg0bKOaD2Hrgw7cwHwYDVR0j
BBgwFoAU4dUZV6haEYrgZg0bKOaD2Hrgw7cwDQYJKoZIhvcNAQEFBQADggIBAK9N
L+FdiQtsJKXjjRl7KiosJ+ez5fFqClzS23dSwXXWiXORTsIlnKfm5xetTPwnebRt
XbyfpdgeQ7x3mjhkfodtyj+of0OCskHLWCXzf3q/8XeGG6aOciQwrFL4KZEpBiQb
p3cMy0LmS+JOgchS37Y5WkXCwFGrHEIbb5X7qaOOmaMsQKoeztv+xPUVxfTb6n+i
2LGAXle6QXbmjhqE67EH2dLlAMVxFGDQIvXkz+mVQu78V10IPL2PTxx4y2ypXo/A
bIAlzhZmpUYvB/Qqs5nj8Hoxtspc9kluYfaSP2/o5QLyhFfxl3hfXyhxW8ngzkhQ
nXjDTqnXzes/ffcNw641gk8Nsb2l4KWicSVxPYcoaXDwn+L63cwCovn7pKiueoSK
gLldhFp/rjSqpYK8tZSGToeEgA1cl2Ia26phVKa5RnB27U0l4LLIZmzDoH9LOEyz
/VQAB3QQYQ7K3obcXraqcLeogf8vGYWChIqLL4nlqmeRrB0lDu/DZ7v5dgKrFws8
EYAmt7loO42lXpdqK6KwyRazDEQY2mCCEQiwGl3o7jri2zT6el6b1aO3gQEvGgf6
DDL5ZheWFybSPMYDdlqTMlrdq7PxhySnoqn0JjKWqJkN+1F0Kms/k6ZM8pqZX3Zm
1M/QwlvmNhXX3X0zORRmgusiV8MPDbiwkp82m335
-----END CERTIFICATE-----
`)

// IBMw3idEndpoint is the TAP pilot endpoint for IBM w3ID authentication.
var IBMw3idTapEndpoint = oauth2.Endpoint{
	AuthURL:  "https://w3id.tap.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/authorize",
	TokenURL: "https://w3id.tap.ibm.com/isam/oidc/endpoint/amapp-runtime-oidcidp/token",
}

// IBMw3idPublicKey is the rsa.PublicKey to use to verify the signature on
// an id_token value returned from IBMw3idTapEndpoint.TokenURL.
var IBMw3idTapPublicKey = pemToRSA(`
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
	oauth2.RegisterBrokenAuthHeaderProvider(IBMw3idStagingEndpoint.TokenURL)
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
		err := cset.Set("email", et)
		if err != nil {
			return cset, fmt.Errorf("error adding email to claimset: %s", err)
		}
	case []interface{}:
		err := cset.Set("email", et[0].(string))
		if err != nil {
			return cset, fmt.Errorf("error adding email to claimset: %s", err)
		}
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
		err := cset.Set(kt, v)
		if err != nil {
			return cset, fmt.Errorf("error adding %s to claimset: %s", kt, err)
		}
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
