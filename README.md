
# OpenID Connect for IBM w3id

This is support code for authenticating using IBM's internal OpenID Connect
authentication servers.

The OpenID Connect parameters for IBMid are provided in the call to `NewIBMidAuthenticator`:

 1. The client ID, given to you during the enrollment process
 2. The client secret, ditto
 3. The callback URL

Example usage:

    ibmid := ibmoidc.NewIBMidAuthenticator(myClientID, myClientSecret, myCallbackURL)

    http.Handle("/login", ibmid.BeginLogin())
    http.Handle("/openid/code", ibmid.CompleteLogin(myauthhandler))

where the callback URL is `https://www.example.com/openid/code` on your web app.

The `http.Handler` `myauthhandler` can then do:

    claimset, ok := ibmoidc.ClaimSetFromRequest(r) // r is the http.Request

The claimset will contain the the authenticated information from IBMid. At that
point it's up to you to work out some way to persist it via a session, cookies,
or whatever.

The useful claimset keys are generally `given_name`, `family_name`, `email`,
`name`, `sub` and `blueGroups`.

Copyright © IBM Corporation 2016-2019.

