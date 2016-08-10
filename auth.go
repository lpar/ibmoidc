package ibmoidc

import (
	"crypto/rsa"
	"log"
	"net/http"
	"os"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
	"github.com/rs/xhandler"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type key int

const userIdentity key = 0

type Authenticator struct {
	OAuth2 *oauth2.Config
	PubKey *rsa.PublicKey
}

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

func (auth *Authenticator) BeginLogin() xhandler.HandlerC {
	return xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		csrftok, err := MakeCSRFtoken()
		if err != nil {
			log.Printf("[ERROR] Unable to make CSRF token: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// We write our CSRF token into a cookie and into the OIDC request
		http.SetCookie(w, MakeCSRFcookie(csrftok))
		url := auth.OAuth2.AuthCodeURL(csrftok, oauth2.AccessTypeOnline)
		log.Printf("[DEBUG] Redirecting user to %s to log in", url)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)

	})
}

func (auth *Authenticator) CompleteLogin(next xhandler.HandlerC) xhandler.HandlerC {
	return xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] loginCallback started")

		// First verify the state value to protect against CSRF attack
		cstate := ReadCSRFcookie(r)
		state := r.FormValue("state")
		if state != cstate {
			log.Printf("Invalid CSRF state, expected %s got %s", cstate, state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		log.Printf("[DEBUG] passed CSRF check")

		// Then use the code we were given to fetch an access token via TLS
		code := r.FormValue("code")
		log.Printf("State = %s, Code = %s", state, code)
		token, err := auth.OAuth2.Exchange(oauth2.NoContext, code)

		if err != nil {
			log.Printf("w3id.Exchange() failed: %s", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		if !token.Valid() {
			log.Printf("w3id.Exchange() returned invalid token")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		log.Printf("[DEBUG] exchanged code for token")

		// Next, extract the encoded id_token from the access token response
		encidtoken := token.Extra("id_token").(string)
		if len(encidtoken) == 0 {
			log.Printf("w3id.Exchange() response missing id_token")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		log.Printf("[DEBUG] got id_token from token")

		// Verify the cryptographic signature on the id_token before using
		// any information in it
		jsonwt, err := jws.Verify([]byte(encidtoken), jwa.RS256, IBMw3idPublicKey)
		if err != nil {
			log.Printf("w3id.Exchange() id_token signature invalid: %s", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		log.Printf("[DEBUG] verified signature on id_token")

		log.Printf("[DEBUG] raw id_token = %s", jsonwt)
		claimset, err := UnmarshalJSON(jsonwt)
		if err != nil {
			log.Printf("w3id.Exchange() id_token JSON unmarshal failed: %s", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// Success, so put the claimset in the Context and call the next
		// function
		ctx = ContextWithClaims(ctx, claimset)
		next.ServeHTTPC(ctx, w, r)
	})
}

func ContextWithClaims(ctx context.Context, cs *jwt.ClaimSet) context.Context {
	return context.WithValue(ctx, userIdentity, cs)
}

func ClaimsFromContext(ctx context.Context) (*jwt.ClaimSet, bool) {
	cs, ok := ctx.Value(userIdentity).(*jwt.ClaimSet)
	return cs, ok
}
