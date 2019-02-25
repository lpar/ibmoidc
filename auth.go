package ibmoidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
	"io/ioutil"
	"net/http"

	"github.com/lpar/blammo/log"

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
// IBMid authentication server responses.
func NewIBMidAuthenticator(clientid, clientsecret, redirecturl string) *Authenticator {
	oauth2 := &oauth2.Config{
		ClientID:     clientid,
		ClientSecret: clientsecret,
		RedirectURL:  redirecturl,
		Endpoint:     IBMidEndpoint,
		Scopes:       []string{"openid"},
	}
	auth := &Authenticator{
		OAuth2: oauth2,
		PubKey: IBMidPublicKey,
	}
	return auth
}


// NewIntranetAuthenticator creates an Authenticator object for processing
// intranet w3ID authentication server responses.
func NewIntranetAuthenticator(clientid, clientsecret, redirecturl string) *Authenticator {
	oauth2 := &oauth2.Config{
		ClientID:     clientid,
		ClientSecret: clientsecret,
		RedirectURL:  redirecturl,
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
func NewIntranetStagingAuthenticator(clientid, clientsecret, redirecturl string) *Authenticator {
	oauth2 := &oauth2.Config{
		ClientID:     clientid,
		ClientSecret: clientsecret,
		RedirectURL:  redirecturl,
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
			log.Error().Err(err).Msg("unable to make CSRF token")
			http.Error(w, "unable to make CSRF token", http.StatusInternalServerError)
			return
		}
		// We write our CSRF token into a cookie and into the OIDC request
		http.SetCookie(w, MakeCSRFcookie(csrftok))
		url := auth.OAuth2.AuthCodeURL(csrftok, oauth2.AccessTypeOnline)
		log.Debug().Str("url", url).Msg("redirecting user to log in")
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
}

func (auth *Authenticator) FetchToken(code string) (*jwt.ClaimSet, error) {
	claimset := &jwt.ClaimSet{}
	token, err := auth.OAuth2.Exchange(context.Background(), code)
	if err != nil {
		return claimset, err
	}
	if !token.Valid() {
		return claimset, errors.New("endpoint oauth2.Exchange returned invalid token")
	}
	log.Debug().Msg("exchanged code for token")

	// Next, extract the encoded id_token from the access token response
	encidtoken := token.Extra("id_token").(string)
	if len(encidtoken) == 0 {
		return claimset, errors.New("endpoint oauth2.Exchange() response missing id_token")
	}
	log.Debug().Msg("got id_token from token")

	_ = ioutil.WriteFile("/tmp/rawidtoken.json", []byte(encidtoken), 0644)

	// Verify the cryptographic signature on the id_token before using
	// any information in it
	jsonwt, err := jws.Verify([]byte(encidtoken), jwa.RS256, auth.PubKey)
	if err != nil {
		return claimset, fmt.Errorf("endpoint oauth2.Exchange() id_token signature invalid: %v", err)
	}
	log.Debug().Msg("verified signature on id_token")

	log.Debug().Str("id_token", string(jsonwt)).Msg("unmarshaling raw token")
	claimset, err = UnmarshalJSON(jsonwt)
	if err != nil {
		return claimset, fmt.Errorf("w3id.Exchange() id_token JSON unmarshal failed: %v", err)
	}
	return claimset, nil
}

// CompleteLoginFunc is the http.HandlerFunc version of CompleteLogin.
// It accepts the HTTP GET response from the federated
// authentication provider and completes the login process by fetching
// identity information from the provider. The verified identity is then
// added to the request context, so that it can be accessed by the next
// handler in the chain using ClaimSetFromRequest.
func (auth *Authenticator) CompleteLoginFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nr := auth.decodeClaimsetToRequest(w, r)
		next(w, nr)
	}
}

// decodeClaimsetToRequest checks the CSRF cookie and fetches the claimset using the token in the response.
// If everything worked, it adds the claimset to the request and returns the new request.
// If not, it returns the same request it was passed.
func (auth *Authenticator) decodeClaimsetToRequest(w http.ResponseWriter, r *http.Request) *http.Request {
	log.Debug().Msg("loginCallback started")

	// First verify the state value to protect against CSRF attack
	cstate := ReadCSRFcookie(r)
	state := r.FormValue("state")
	if state != cstate {
		log.Debug().Str("expected", cstate).Str("got", state).Msg("invalid CSRF state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return r
	}

	log.Debug().Msg("passed CSRF check")

	// Then use the code we were given to fetch an access token via TLS
	code := r.FormValue("code")
	claimset, err := auth.FetchToken(code)
	if err != nil {
		log.Error().Err(err).Msg("login failed")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return r
	}
  nr := RequestWithClaimSet(r, claimset)
	return nr
}

// CompleteLogin accepts the HTTP GET response from the federated
// authentication provider and completes the login process by fetching
// identity information from the provider. The verified identity is then
// added to the request context, so that it can be accessed by the next
// handler in the chain using ClaimSetFromRequest.
func (auth *Authenticator) CompleteLogin(next http.Handler) http.Handler {
	return http.HandlerFunc( func(w http.ResponseWriter, r *http.Request) {
		nr := auth.decodeClaimsetToRequest(w, r)
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
