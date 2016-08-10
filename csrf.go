package ibmoidc

// CSRF protection utility functions for OpenID Connect login flow.

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// MakeCSRFtoken makes a random 32-character string for use as a CSRF token.
func MakeCSRFtoken() (string, error) {
	b, err := randomBytes(32)
	return base64.URLEncoding.EncodeToString(b), err
}

const myCSRFCookieName = "csrf"

// MakeCSRFcookie turns a string generated by MakeCSRFtoken into a CSRF cookie.
func MakeCSRFcookie(tok string) *http.Cookie {
	return &http.Cookie{
		Name:     myCSRFCookieName,
		HttpOnly: true,
		Value:    tok,
		Path:     "/",
	}
}

// ReadCSRFcookie gets the token from the CSRF cookie, if found.
func ReadCSRFcookie(r *http.Request) string {
	cl := r.Cookies()
	for _, c := range cl {
		if c.Name == myCSRFCookieName {
			return c.Value
		}
	}
	return ""
}
