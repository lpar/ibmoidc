package ibmoidc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
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
	oa2 := &oauth2.Config{
		ClientID:     clientid,
		ClientSecret: clientsecret,
		RedirectURL:  redirecturl,
		Endpoint:     IBMidEndpoint,
		Scopes:       []string{"openid"},
	}
	auth := &Authenticator{
		OAuth2: oa2,
		PubKey: IBMidPublicKey,
	}
	return auth
}


// NewIntranetAuthenticator creates an Authenticator object for processing
// intranet w3ID authentication server responses.
func NewIntranetAuthenticator(clientid, clientsecret, redirecturl string) *Authenticator {
	oa2 := &oauth2.Config{
		ClientID:     clientid,
		ClientSecret: clientsecret,
		RedirectURL:  redirecturl,
		Endpoint:     IBMw3idEndpoint,
		Scopes:       []string{"openid"},
	}
	auth := &Authenticator{
		OAuth2: oa2,
		PubKey: IBMw3idPublicKey,
	}
	return auth
}

// NewIntranetStagingAuthenticator creates an Authenticator object for processing
// intranet w3ID authentication server responses from the staging server.
func NewIntranetStagingAuthenticator(clientid, clientsecret, redirecturl string) *Authenticator {
	oa2 := &oauth2.Config{
		ClientID:     clientid,
		ClientSecret: clientsecret,
		RedirectURL:  redirecturl,
		Endpoint:     IBMw3idStagingEndpoint,
		Scopes:       []string{"openid"},
	}
	auth := &Authenticator{
		OAuth2: oa2,
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

func (auth *Authenticator) FetchToken(code string) (*jwt.Token, error) {
	var jsonwt *jwt.Token
	token, err := auth.OAuth2.Exchange(context.Background(), code)
	if err != nil {
		return jsonwt, err
	}
	if !token.Valid() {
		return jsonwt, errors.New("endpoint oauth2.Exchange returned invalid token")
	}
	log.Debug().Msg("exchanged code for token")

	// Next, extract the encoded id_token from the access token response
	encidtoken := token.Extra("id_token").(string)
	if len(encidtoken) == 0 {
		return jsonwt, errors.New("endpoint oauth2.Exchange() response missing id_token")
	}
	log.Debug().Msg("got id_token from token")
	jsonwt, err = jwt.ParseVerify(bytes.NewReader([]byte(encidtoken)), jwa.RS256, auth.PubKey)
	if err != nil {
		return jsonwt, fmt.Errorf("endpoint oauth2.Exchange() id_token invalid: %v", err)
	}
	log.Debug().Msg("verified signature on id_token")
	return jsonwt, nil
}

// CompleteLoginFunc is the http.HandlerFunc version of CompleteLogin.
// It accepts the HTTP GET response from the federated
// authentication provider and completes the login process by fetching
// identity information from the provider. The verified identity is then
// added to the request context, so that it can be accessed by the next
// handler in the chain using TokenFromRequest.
func (auth *Authenticator) CompleteLoginFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nr := auth.decodeTokenToRequest(w, r)
		next(w, nr)
	}
}

// decodeTokenToRequest checks the CSRF cookie and fetches the token.
// If everything worked, it adds the token to the request and returns the new request.
// If not, it returns the same request it was passed.
func (auth *Authenticator) decodeTokenToRequest(w http.ResponseWriter, r *http.Request) *http.Request {
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
	tok, err := auth.FetchToken(code)
	if err != nil {
		log.Error().Err(err).Msg("login failed")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return r
	}
  nr := RequestWithToken(r, tok)
	return nr
}

// CompleteLogin accepts the HTTP GET response from the federated
// authentication provider and completes the login process by fetching
// identity information from the provider. The verified identity is then
// added to the request context, so that it can be accessed by the next
// handler in the chain using TokenFromRequest.
func (auth *Authenticator) CompleteLogin(next http.Handler) http.Handler {
	return http.HandlerFunc( func(w http.ResponseWriter, r *http.Request) {
		nr := auth.decodeTokenToRequest(w, r)
		next.ServeHTTP(w, nr)
	})
}

// RequestWithToken adds a token to the http request, using a private
// context key.
func RequestWithToken(r *http.Request, cs *jwt.Token) *http.Request {
	ctx := r.Context()
	nctx := context.WithValue(ctx, userIdentity, cs)
	nr := r.WithContext(nctx)
	return nr
}

// TokenFromRequest obtains the authenticated token from the request's
// context, where it was stored earlier by RequestWithToken.
// The boolean indicates whether an authenticated token was actually found
// in the request.
func TokenFromRequest(r *http.Request) (*jwt.Token, bool) {
	ctx := r.Context()
	cs, ok := ctx.Value(userIdentity).(*jwt.Token)
	return cs, ok
}
