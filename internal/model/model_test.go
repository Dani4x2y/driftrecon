package model

import (
	"encoding/json"
	"testing"
)

func TestServiceKey(t *testing.T) {
	if got, want := ServiceKey("https", "api.example.com", 443), "https://api.example.com:443"; got != want {
		t.Errorf("ServiceKey = %q, want %q", got, want)
	}
	if got, want := ServiceKey("http", "api.example.com", 8080), "http://api.example.com:8080"; got != want {
		t.Errorf("ServiceKey = %q, want %q", got, want)
	}
}

func TestSimHashIsStoredAsHexText(t *testing.T) {
	// The value does not fit a signed 64-bit integer nor a float64, which is
	// what a JSON number would be read back as.
	h := SimHash(0xfedcba9876543210)
	page := Page{SimHash: &h}

	doc, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"simhash":"fedcba9876543210"}`; string(doc) != want {
		t.Fatalf("encoded = %s, want %s", doc, want)
	}

	var back Page
	if err := json.Unmarshal(doc, &back); err != nil {
		t.Fatal(err)
	}
	if back.SimHash == nil || *back.SimHash != h {
		t.Errorf("decoded = %v, want %v", back.SimHash, h)
	}

	if got := SimHash(0x2a).String(); got != "000000000000002a" {
		t.Errorf("String = %q, want fixed width", got)
	}
	for _, bad := range []string{`{"simhash":"xyz"}`, `{"simhash":"1ffffffffffffffff"}`, `{"simhash":""}`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

func TestEmptyObservationEncodesCompactly(t *testing.T) {
	doc, err := json.Marshal(ServiceObservation{URL: "http://a.example.com:80", Error: "timeout"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"url":"http://a.example.com:80","error":"timeout"}`; string(doc) != want {
		t.Errorf("encoded = %s, want %s", doc, want)
	}
}

func TestFormHasPassword(t *testing.T) {
	login := Form{Fields: []FormField{{Type: "text", Name: "user"}, {Type: "password", Name: "pass"}}}
	search := Form{Fields: []FormField{{Type: "search", Name: "q"}}}
	if !login.HasPassword() || search.HasPassword() {
		t.Errorf("HasPassword: login = %v, search = %v", login.HasPassword(), search.HasPassword())
	}
}
