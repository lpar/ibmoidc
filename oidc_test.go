package ibmoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/oauth2/jws"
)

func TestDecode(t *testing.T) {

	prikey, err := rsa.GenerateKey(rand.Reader, 1024)

	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}

	payload := &jws.ClaimSet{
		Iss: "http://example.com/",
		Aud: "www.example.com",
		Exp: 1496524688,
		Iat: 1464988688,
		Sub: "jwt@example.com",
		PrivateClaims: map[string]interface{}{
			"firstName":    "Jason",
			"lastName":     "Webb-Toucan",
			"emailAddress": "jwt@example.com",
			"realmName":    "w3id",
			"cn":           "Jason Webb-Toucan",
			"clientIP":     "2600:1114:a651:4900:56ee:75ff:fe4a:3f67",
		},
	}

	idtok, err := jws.Encode(header, payload, prikey)

	err = jws.Verify(idtok, &prikey.PublicKey)
	if err != nil {
		t.Error("Failed to verify cryptographic signature on known good id_token")
	}

	cs, err := Decode(idtok)
	if err != nil {
		t.Error("Failed to decode id_token claim set")
	}

	if cs.Sub != "jwt@example.com" {
		t.Error("Decoded id_token had wrong subject")
	}
	e := cs.EmailAddress
	if e != "jwt@example.com" {
		t.Error("Decoded id_token email address was wrong")
	}
	if cs.FirstName != "Jason" || cs.LastName != "Webb-Toucan" || cs.CN != "Jason Webb-Toucan" {
		t.Error("Decoded id_token had wrong name")
	}

	badtok := `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3czaWQudGFwLmlibS5jb20vaXNhbSIsImF0X2hhc2giOiJMam1iZF85dXdZX3NaTUxNbnBSbmVnIiwic3ViIjoidGp3YXRzb25AdXMuaWJtLmNvbSIsImxhc3ROYW1lIjoiV2F0c29uIiwicmVhbG1OYW1lIjoiVzNJRFJlYWxtIiwidXNlckFnZW50IjoiTW96aWxsYS81LjAgKFgxMTsgRmVkb3JhOyBMaW51eCB4ODZfNjQ7IHJ2OjQ2LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvNDYuMCIsImRuIjoidWlkPTkwMTI1MDg5NyxjPXVzLG91PWJsdWVwYWdlcyxvPWlibS5jb20iLCJjbiI6IlRob21hcyBKIFdhdHNvbiIsImF1ZCI6Ik9ESm1OalprWlRJdE0ySXdaaTAwIiwiZmlyc3ROYW1lIjoiVGhvbWFzIiwiZW1haWxBZGRyZXNzIjpbInRqd2F0c29uQHVzLmlibS5jb20iXSwiY2xpZW50SVAiOiIxNjkuNTQuMzAuMTcyIiwiZXhwIjoxNDY0ODg4NzA3LCJhdXRoTWV0aG9kIjoiZmFpbG92ZXItZXh0LWF1dGgtaW50ZXJmYWNlIiwiaWF0IjoxNDY0ODgxNTA3fQ.BUSKKNp8NO7AeX05cpfW3xQJ5kiSTydJKzLR8ZDeI2LaUUOILkMoy3OxW0xnA4OpRyowcqrmYLcti0IHrZjuhX6yJcCuJARembeNUTnUWWoHmxOyFnUaWVyUV82m5kx7MC2cIvjVvgGCTAV7V7WqEFjogkY9cOyRgYbTHdYFSRJvNdx6rUVrR0sXGYDVQUaJWFLMkqNo4HXMUmSf2SDjpbnrib8Xat5xcIUPk9jd7YTU1S4y_UP6MwipgXUgSVqJreTDhxorVXrLjMvF-P7F6bd1SJu0-khRvUPG41Pl_-QWuzo83zy8KOLLDVjBCNwKpiGywvyJT5QykxYEslWvQg`

	err = jws.Verify(badtok, IBMw3idPublicKey)
	if err == nil {
		t.Error("Verified cryptographic signature on known bad id_token!")
	}

	_, err = Decode(badtok)
	if err == nil {
		t.Error("Decoded id_token with bad cryptographic signature")
	}

}
