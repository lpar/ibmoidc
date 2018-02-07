
# OpenID Connect for IBM w3id

This is support code for authenticating using IBM's internal OpenID Connect
authentication servers.

The OpenID Connect parameters for w3ID are taken from environment variables:

		W3ID_CLIENTID
    W3ID_CLIENTSECRET
    W3ID_CALLBACKURL

Example usage:

  	w3id := ibmoidc.NewIntranetAuthenticator()

  	http.Handle("/login", w3id.BeginLogin())
		http.Handle("/openid/code", w3id.CompleteLogin(myauthhandler))

where `W3ID_CALLBACKURL` is `https://www.example.com/openid/code` on your web app.

The `http.Handler` myauthhandler can then do:

    claimset, ok := ibmoidc.ClaimSetFromRequest(r) // r is the http.Request

The claimset will contain the the authenticated information from w3ID. At that
point it's up to you to work out some way to persist it via a session, cookies,
or whatever.

The useful claimset keys are generally `given_name`, `family_name`, `email`,
`name`, `sub` and `blueGroups`.

Copyright © IBM Corporation 2016-2018.
