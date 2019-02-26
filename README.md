
# OpenID Connect for IBMid

This is support code for authenticating using IBM's OpenID Connect
authentication servers, in particular IBMid.

The OpenID Connect parameters for IBMid are provided in the call to `NewIBMidAuthenticator`:

 1. The client ID, given to you during the enrollment process
 2. The client secret, ditto
 3. The callback URL

Example usage:

```go
ibmid := ibmoidc.NewIBMidAuthenticator(myClientID, myClientSecret, myCallbackURL)

http.Handle("/login", ibmid.BeginLogin())
http.Handle("/openid/code", ibmid.CompleteLogin(myauthhandler))
````

where the callback URL is `https://www.example.com/openid/code` on your web app.

The `http.Handler` `myauthhandler` can then do:

```go
token, ok := ibmoidc.TokenFromRequest(r) // r is the http.Request
````

The `jwt.Token` in `token` will contain the the authenticated information from
IBMid. At that point it's up to you to work out some way to persist it via a
session, cookies, or whatever.

It's also up to you to access and unpack the `ext` parameter from the JWT,
which contains JSON you can deserialize in order to obtain the BlueGroups
information.

Here's an example of how you might turn the token into a User object:

```go
type User struct {
  Name       string
  Email      string
  Company    string
  BlueGroups []string
}

func getString(tok *jwt.Token, key string) string {
  x, ok := tok.Get(key)
  if !ok {
    return ""
  }
  switch v := x.(type) {
  case string:
    return v
  default:
    return ""
  }
}

func NewUser(tok *jwt.Token) *User {
  type Ext struct {
    BlueGroups []string `json:"blueGroups"`
    Company    string   `json:"company"`
  }
  user := &User{}
  extjson, ok := tok.Get("ext")
  if ok {
    extstr := extjson.(string)
    ext := Ext{}
    err := json.Unmarshal([]byte(extstr), &ext)
    if err == nil {
      user.Company = ext.Company
      user.BlueGroups = ext.BlueGroups
    }
  }
  user.Email = getString(tok, "email")
  user.Name = getString(tok, "name")
  return user
}
```

Copyright © IBM Corporation 2016-2019.

