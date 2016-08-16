package ibmoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strconv"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
)

func makeTestClaimSet() *jwt.ClaimSet {
	cs := jwt.NewClaimSet()

	cs.Construct(map[string]interface{}{
		"iss": "http://example.com/",
		"exp": 1496524688,
		"iat": 1464988688,
		"sub": "jwt@example.com",
	})

	cs.Set("aud", []string{"www.example.com"})

	cs.PrivateClaims = map[string]interface{}{
		"firstName":    "Jason",
		"lastName":     "Webb-Toucan",
		"emailAddress": "jwt@example.com",
		"realmName":    "w3id",
		"cn":           "Jason Webb-Toucan",
		"dn":           "jwt@example.com",
		"clientIP":     "2600:1114:a651:4900:56ee:75ff:fe4a:3f67",
	}
	return cs
}

func TestDecode(t *testing.T) {

	prikey, err := rsa.GenerateKey(rand.Reader, 1024)

	payload := makeTestClaimSet()

	jpay, err := payload.MarshalJSON()
	if err != nil {
		t.Error("Failed to marshal claimset payload: %s", err)
	}

	idtok, err := jws.Sign(jpay, jwa.RS256, prikey)

	verified, err := jws.Verify(idtok, jwa.RS256, &prikey.PublicKey)
	if err != nil {
		t.Error("Error checking cryptographic signature on known good id_token: %s", err)
	}

	cs, err := UnmarshalJSON(verified)
	if err != nil {
		t.Error("Failed to decode id_token claim set")
	}

	if cs.Subject != "jwt@example.com" {
		t.Errorf("Decoded id_token had wrong subject, got %s", cs.Subject)
	}
	e := cs.Get("email")
	if e != "jwt@example.com" {
		t.Errorf("Decoded id_token email address was wrong, got %s", e)
	}
	fn := cs.Get("given_name")
	if cs.Get("given_name") != "Jason" {
		t.Error("Decoded id_token had wrong given_name, expected Jason got %s", fn)
	}

	ln := cs.Get("family_name")
	if ln != "Webb-Toucan" {
		t.Error("Decoded id_token had wrong family_name, expected Webb-Toucan got %s", ln)
	}
	cn := cs.Get("name")
	if cn != "Jason Webb-Toucan" {
		t.Error("Decoded id_token had wrong name, expected Jason Webb-Toucan got %s", cn)
	}

	badtok := []byte(`eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3czaWQudGFwLmlibS5jb20vaXNhbSIsImF0X2hhc2giOiJMam1iZF85dXdZX3NaTUxNbnBSbmVnIiwic3ViIjoidGp3YXRzb25AdXMuaWJtLmNvbSIsImxhc3ROYW1lIjoiV2F0c29uIiwicmVhbG1OYW1lIjoiVzNJRFJlYWxtIiwidXNlckFnZW50IjoiTW96aWxsYS81LjAgKFgxMTsgRmVkb3JhOyBMaW51eCB4ODZfNjQ7IHJ2OjQ2LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvNDYuMCIsImRuIjoidWlkPTkwMTI1MDg5NyxjPXVzLG91PWJsdWVwYWdlcyxvPWlibS5jb20iLCJjbiI6IlRob21hcyBKIFdhdHNvbiIsImF1ZCI6Ik9ESm1OalprWlRJdE0ySXdaaTAwIiwiZmlyc3ROYW1lIjoiVGhvbWFzIiwiZW1haWxBZGRyZXNzIjpbInRqd2F0c29uQHVzLmlibS5jb20iXSwiY2xpZW50SVAiOiIxNjkuNTQuMzAuMTcyIiwiZXhwIjoxNDY0ODg4NzA3LCJhdXRoTWV0aG9kIjoiZmFpbG92ZXItZXh0LWF1dGgtaW50ZXJmYWNlIiwiaWF0IjoxNDY0ODgxNTA3fQ.BUSKKNp8NO7AeX05cpfW3xQJ5kiSTydJKzLR8ZDeI2LaUUOILkMoy3OxW0xnA4OpRyowcqrmYLcti0IHrZjuhX6yJcCuJARembeNUTnUWWoHmxOyFnUaWVyUV82m5kx7MC2cIvjVvgGCTAV7V7WqEFjogkY9cOyRgYbTHdYFSRJvNdx6rUVrR0sXGYDVQUaJWFLMkqNo4HXMUmSf2SDjpbnrib8Xat5xcIUPk9jd7YTU1S4y_UP6MwipgXUgSVqJreTDhxorVXrLjMvF-P7F6bd1SJu0-khRvUPG41Pl_-QWuzo83zy8KOLLDVjBCNwKpiGywvyJT5QykxYEslWvQg`)

	verified, err = jws.Verify(badtok, jwa.RS256, IBMw3idPublicKey)
	if err == nil {
		t.Error("Verified cryptographic signature on known bad id_token!")
	}

	// Should still decode even if signature is bad
	_, err = Decode(badtok)
	if err != nil {
		t.Error("Failed to decode id_token with bad cryptographic signature")
	}

}

// Make sure we can handle emailAddress being an array or a string
func TestEmailFlexibility(t *testing.T) {

	json1 := []byte(`{"iss": "https://w3id.tap.ibm.com/isam",
  "aud": "ODJmNsyoyodynelwZi00",
  "exp": 1469566949,
  "iat": 1469559749,
  "sub": "parrot@example.com",
  "lastName": "Parrot",
  "firstName": "John",
  "cn": "John Parrot",
  "dn": "parrot@example.com",
  "realmName": "W3IDRealm",
  "emailAddress": ["john@example.com", "parrot@example.com"],
  "clientIP": "10.0.0.2"}`)

	json2 := []byte(`{"iss": "https://w3id.tap.ibm.com/isam",
  "aud": "ODJmNsyoyodynelwZi00",
  "exp": 1469566949,
  "iat": 1469559749,
  "sub": "parrot@example.com",
  "lastName": "Parrot",
  "firstName": "John",
  "cn": "John Parrot",
  "dn": "parrot@example.com",
  "realmName": "W3IDRealm",
  "emailAddress": "john@example.com",
  "clientIP": "10.0.0.2"}`)

	cs1, err1 := UnmarshalJSON(json1)
	cs2, err2 := UnmarshalJSON(json2)

	if err1 != nil {
		t.Errorf("array emailAddress deserialize failed with error %s", err1)
	}
	if err2 != nil {
		t.Errorf("string emailAddress deserialize failed with error %s", err2)
	}

	if cs1.Get("email") != "john@example.com" {
		t.Errorf("array emailAddress deserialize gave wrong value, expected john@example.com got %s", cs1.Get("email"))
	}

	if cs2.Get("email") != "john@example.com" {
		t.Errorf("string emailAddress deserialize gave wrong value, expected john@example.com got %s", cs2.Get("email"))
	}

}

func getString(t *testing.T, cs *jwt.ClaimSet, key string) string {
	x := cs.Get(key)
	switch v := x.(type) {
	case string:
		return v
	case int64:
		return strconv.Itoa(int(v))
	case []string:
		if len(v) > 0 {
			return v[0]
		}
		t.Errorf("empty slice in claim %s: %+v", key, x)
	default:
		t.Errorf("unexpected claim data type %+v", x)
	}
	return ""
}

func TestContextHandling(t *testing.T) {
	cs := makeTestClaimSet()
	req, err := http.NewRequest("GET", "http://www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	nreq := RequestWithClaimSet(req, cs)
	ncs, ok := ClaimSetFromRequest(nreq)
	if !ok {
		t.Error("Didn't find claimset in request")
	}

	claims := []string{"iss", "aud", "exp", "iat", "sub", "firstName", "lastName", "emailAddress", "realmName", "cn", "dn", "clientIP"}

	for _, cname := range claims {
		before := getString(t, cs, cname)
		if before == "" {
			t.Errorf("claim %s empty in test value", cname)
		}
		after := getString(t, ncs, cname)
		if before != after {
			t.Errorf("claim %s mangled, expected %s got %s", cname, before, after)
		}
	}
}
