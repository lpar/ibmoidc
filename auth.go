package ibmoidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"

	"github.com/lpar/log"

	"golang.org/x/oauth2"
)

type key int

const userIdentity key = 0

// Authenticator is an object for processing IBM authentication responses.
type Authenticator struct {
	OAuth2 *oauth2.Config
	PubKey *rsa.PublicKey
}

// NewIntranetAuthenticator creates an Authenticator object for processing
// intranet w3ID authentication server responses.
func NewIntranetAuthenticator() *Authenticator {
	oauth2 := &oauth2.Config{
		ClientID:     os.Getenv("W3ID_CLIENTID"),
		ClientSecret: os.Getenv("W3ID_CLIENTSECRET"),
		RedirectURL:  os.Getenv("W3ID_CALLBACKURL"),
		Endpoint:     IBMw3idEndpoint,
		Scopes:       []string{"openid"},
	}
	auth := &Authenticator{
		OAuth2: oauth2,
		PubKey: IBMw3idPublicKey,
	}
	return auth
}

// NewIntranetStagingAuthenticator creates an Authenticator object for processing
// intranet w3ID authentication server responses from the staging server.
func NewIntranetStagingAuthenticator() *Authenticator {
	oauth2 := &oauth2.Config{
		ClientID:     os.Getenv("W3ID_CLIENTID"),
		ClientSecret: os.Getenv("W3ID_CLIENTSECRET"),
		RedirectURL:  os.Getenv("W3ID_CALLBACKURL"),
		Endpoint:     IBMw3idStagingEndpoint,
		Scopes:       []string{"openid"},
	}
	auth := &Authenticator{
		OAuth2: oauth2,
		PubKey: IBMw3idStagingPublicKey,
	}
	return auth
}

// BeginLogin redirects the browser to the federated authentication provider
// in order to begin the login process.
func (auth *Authenticator) BeginLogin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csrftok, err := MakeCSRFtoken()
		if err != nil {
			http.Error(w, log.Errorf("Unable to make CSRF token: %s", err).Error(), http.StatusInternalServerError)
			return
		}
		// We write our CSRF token into a cookie and into the OIDC request
		http.SetCookie(w, MakeCSRFcookie(csrftok))
		url := auth.OAuth2.AuthCodeURL(csrftok, oauth2.AccessTypeOnline)
		log.Debugf("Redirecting user to %s to log in", url)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
}

func (auth *Authenticator) FetchToken(code string) (*jwt.ClaimSet, error) {
	claimset := &jwt.ClaimSet{}
	token, err := auth.OAuth2.Exchange(oauth2.NoContext, code)
	if err != nil {
		return claimset, err
	}
	if !token.Valid() {
		return claimset, errors.New("w3id.Exchange returned invalid token")
	}
	log.Debugf("exchanged code for token")

	// Next, extract the encoded id_token from the access token response
	encidtoken := token.Extra("id_token").(string)
	if len(encidtoken) == 0 {
		return claimset, errors.New("w3id.Exchange() response missing id_token")
	}
	log.Debugf("got id_token from token")

	// Verify the cryptographic signature on the id_token before using
	// any information in it
	jsonwt, err := jws.Verify([]byte(encidtoken), jwa.RS256, auth.PubKey)
	if err != nil {
		return claimset, log.Errorf("w3id.Exchange() id_token signature invalid: %v", err)
	}
	log.Debugf("verified signature on id_token")

	log.Debugf("raw id_token = %s", jsonwt)
	claimset, err = UnmarshalJSON(jsonwt)
	if err != nil {
		return claimset, fmt.Errorf("w3id.Exchange() id_token JSON unmarshal failed: %v", err)
	}
	return claimset, nil
}

// CompleteLogin accepts the HTTP GET response from the federated
// authentication provider and completes the login process by fetching
// identity information from the provider. The verified identity is then
// added to the request context, so that it can be accessed by the next
// handler in the chain using ClaimSetFromRequest.
func (auth *Authenticator) CompleteLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("loginCallback started")

		// First verify the state value to protect against CSRF attack
		cstate := ReadCSRFcookie(r)
		state := r.FormValue("state")
		if state != cstate {
			log.Debugf("Invalid CSRF state, expected %s got %s", cstate, state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		log.Debugf("passed CSRF check")

		// Then use the code we were given to fetch an access token via TLS
		code := r.FormValue("code")
		claimset, err := auth.FetchToken(code)
		if err != nil {
			log.Errorf("login failed: %v", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}

		// Success, so put the claimset in the Context and call the next
		// function
		nr := RequestWithClaimSet(r, claimset)
		next.ServeHTTP(w, nr)
	})
}

// RequestWithClaimSet adds a claimset to the http request, using a private
// context key.
func RequestWithClaimSet(r *http.Request, cs *jwt.ClaimSet) *http.Request {
	ctx := r.Context()
	nctx := context.WithValue(ctx, userIdentity, cs)
	nr := r.WithContext(nctx)
	return nr
}

// ClaimSetFromRequest obtains the authenticated claimset from the request's
// context, where it was stored earlier by RequestWithClaimSet.
// The boolean indicates whether an authenticated claimset was actually found
// in the request.
func ClaimSetFromRequest(r *http.Request) (*jwt.ClaimSet, bool) {
	ctx := r.Context()
	cs, ok := ctx.Value(userIdentity).(*jwt.ClaimSet)
	return cs, ok
}
