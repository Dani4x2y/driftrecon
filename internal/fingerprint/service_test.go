package fingerprint

import (
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func leafCert() *model.Certificate {
	return &model.Certificate{
		SHA256:     "aa11",
		SubjectCN:  "www.example.com",
		IssuerCN:   "R11",
		IssuerOrg:  "Let's Encrypt",
		Serial:     "04d2",
		SANs:       []string{"www.example.com", "example.com"},
		SPKISHA256: "bb22",
		NotBefore:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		KeyAlg:     "ECDSA-P256",
	}
}

func serviceObservation() model.ServiceObservation {
	simhash := model.SimHash(0xb58b71ccd6ca55eb)
	return model.ServiceObservation{
		URL: "https://www.example.com:443",
		TLS: &model.TLS{
			Version: "TLS 1.3",
			Cipher:  "TLS_AES_128_GCM_SHA256",
			ALPN:    "h2",
			Chain:   []string{"aa11", "cc33"},
		},
		Hops: []model.Hop{
			{Status: 302, Location: "https://www.example.com/login?next", Relation: model.RelSameOrigin},
			{Status: 200},
		},
		Headers: &model.Headers{
			Names: []string{"Server", "Date", "Content-Type", "Set-Cookie", "Strict-Transport-Security"},
			Values: map[string]string{
				"server":                    "nginx/1.24.0",
				"strict-transport-security": "max-age=31536000",
			},
			Cookies: []model.Cookie{
				{Name: "session", Flags: []string{"httponly", "secure"}},
				{Name: "lang"},
			},
		},
		Page: &model.Page{
			ContentType: "text/html",
			Title:       "Sign in",
			Skeleton:    "dd44",
			SimHash:     &simhash,
			Forms: []model.Form{{
				Method: "POST",
				Action: "/login",
				Fields: []model.FormField{{Type: "hidden", Name: "csrf"}, {Type: "password", Name: "password"}, {Type: "text", Name: "user"}},
			}},
			Scripts:    []string{"https://www.example.com/static/app.js"},
			BodySHA256: "ee55",
		},
	}
}

type mutation struct {
	name   string
	change func(*model.ServiceObservation, *model.Certificate)
}

// checkLayer applies each mutation to a fresh observation and reports
// whether the selected layer changed.
func checkLayer(t *testing.T, layer func(Layers) string, wantChange bool, mutations []mutation) {
	t.Helper()
	base := layer(Service(serviceObservation(), leafCert()))
	if base == "" {
		t.Fatal("layer is empty for a complete observation")
	}
	for _, m := range mutations {
		obs, leaf := serviceObservation(), leafCert()
		m.change(&obs, leaf)
		if changed := layer(Service(obs, leaf)) != base; changed != wantChange {
			t.Errorf("%s: layer changed = %v, want %v", m.name, changed, wantChange)
		}
	}
}

func TestTLSLayer(t *testing.T) {
	layer := func(l Layers) string { return l.TLS }

	checkLayer(t, layer, false, []mutation{
		{"renewal with the same key", func(_ *model.ServiceObservation, c *model.Certificate) {
			c.SHA256, c.Serial = "ff66", "10e1"
			c.NotBefore, c.NotAfter = c.NotBefore.AddDate(0, 2, 0), c.NotAfter.AddDate(0, 2, 0)
		}},
		{"san order", func(_ *model.ServiceObservation, c *model.Certificate) {
			c.SANs = []string{"example.com", "www.example.com"}
		}},
		{"other intermediate", func(o *model.ServiceObservation, _ *model.Certificate) { o.TLS.Chain[1] = "9999" }},
		{"other cipher suite", func(o *model.ServiceObservation, _ *model.Certificate) { o.TLS.Cipher = "TLS_AES_256_GCM_SHA384" }},
	})

	checkLayer(t, layer, true, []mutation{
		{"new key", func(_ *model.ServiceObservation, c *model.Certificate) { c.SPKISHA256 = "0000" }},
		{"new issuer", func(_ *model.ServiceObservation, c *model.Certificate) {
			c.IssuerOrg, c.IssuerCN = "DigiCert Inc", "DigiCert G2"
		}},
		{"issuer name moved between fields", func(_ *model.ServiceObservation, c *model.Certificate) { c.IssuerOrg, c.IssuerCN = "", "Let's Encrypt" }},
		{"name added", func(_ *model.ServiceObservation, c *model.Certificate) { c.SANs = append(c.SANs, "admin.example.com") }},
		{"name removed", func(_ *model.ServiceObservation, c *model.Certificate) { c.SANs = c.SANs[:1] }},
		{"key type", func(_ *model.ServiceObservation, c *model.Certificate) { c.KeyAlg = "RSA-2048" }},
		{"protocol downgrade", func(o *model.ServiceObservation, _ *model.Certificate) { o.TLS.Version = "TLS 1.2" }},
		{"alpn", func(o *model.ServiceObservation, _ *model.Certificate) { o.TLS.ALPN = "http/1.1" }},
		{"trust problem", func(o *model.ServiceObservation, _ *model.Certificate) { o.TLS.Issues = []string{model.IssueUntrusted} }},
	})
}

func TestHeadersLayer(t *testing.T) {
	layer := func(l Layers) string { return l.Headers }

	checkLayer(t, layer, false, []mutation{
		{"cookie order", func(o *model.ServiceObservation, _ *model.Certificate) {
			c := o.Headers.Cookies
			c[0], c[1] = c[1], c[0]
		}},
		{"cookie flag order", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Headers.Cookies[0].Flags = []string{"secure", "httponly"}
		}},
	})

	checkLayer(t, layer, true, []mutation{
		{"header order", func(o *model.ServiceObservation, _ *model.Certificate) {
			n := o.Headers.Names
			n[0], n[1] = n[1], n[0]
		}},
		{"header spelling", func(o *model.ServiceObservation, _ *model.Certificate) { o.Headers.Names[0] = "server" }},
		{"header added", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Headers.Names = append(o.Headers.Names, "X-Cache")
		}},
		{"header removed", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Headers.Names = o.Headers.Names[:4]
		}},
		{"server version", func(o *model.ServiceObservation, _ *model.Certificate) { o.Headers.Values["server"] = "nginx/1.26.1" }},
		{"policy weakened", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Headers.Values["strict-transport-security"] = "max-age=0"
		}},
		{"policy removed", func(o *model.ServiceObservation, _ *model.Certificate) {
			delete(o.Headers.Values, "strict-transport-security")
		}},
		{"cookie flag dropped", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Headers.Cookies[0].Flags = []string{"httponly"}
		}},
		{"cookie added", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Headers.Cookies = append(o.Headers.Cookies, model.Cookie{Name: "tracking"})
		}},
	})
}

func TestRedirectLayer(t *testing.T) {
	layer := func(l Layers) string { return l.Redirect }

	checkLayer(t, layer, true, []mutation{
		{"final status", func(o *model.ServiceObservation, _ *model.Certificate) { o.Hops[1].Status = 403 }},
		{"redirect status", func(o *model.ServiceObservation, _ *model.Certificate) { o.Hops[0].Status = 301 }},
		{"target", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Hops[0].Location = "https://www.example.com/sso?next"
		}},
		{"leaves the scope", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Hops = []model.Hop{{Status: 302, Location: "https://login.example.org/", Relation: model.RelExternal}}
		}},
		{"no longer redirects", func(o *model.ServiceObservation, _ *model.Certificate) { o.Hops = o.Hops[1:] }},
	})
}

func TestDOMLayer(t *testing.T) {
	layer := func(l Layers) string { return l.DOM }

	checkLayer(t, layer, false, []mutation{
		{"title", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Title = "Welcome" }},
		{"text", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.BodySHA256 = "1234" }},
		{"script", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Scripts = nil }},
		{"simhash", func(o *model.ServiceObservation, _ *model.Certificate) { *o.Page.SimHash ^= 1 }},
	})

	checkLayer(t, layer, true, []mutation{
		{"skeleton", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Skeleton = "0000" }},
		{"form removed", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Forms = nil }},
		{"form target", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Forms[0].Action = "/auth" }},
		{"form method", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Forms[0].Method = "GET" }},
		{"field added", func(o *model.ServiceObservation, _ *model.Certificate) {
			o.Page.Forms[0].Fields = append(o.Page.Forms[0].Fields, model.FormField{Type: "text", Name: "otp"})
		}},
		{"field type", func(o *model.ServiceObservation, _ *model.Certificate) { o.Page.Forms[0].Fields[2].Type = "email" }},
	})
}

func TestDOMLayerOfVolatileDocument(t *testing.T) {
	obs := serviceObservation()
	obs.Page.Skeleton = ""
	if got := Service(obs, leafCert()).DOM; got != "" {
		t.Errorf("layer = %q, want none for a document without a stable skeleton", got)
	}
}

func TestDOMLayerOfOtherContent(t *testing.T) {
	page := func(contentType, body string) model.ServiceObservation {
		return model.ServiceObservation{Page: &model.Page{ContentType: contentType, BodySHA256: body}}
	}
	base := Service(page("application/json", "aaaa"), nil).DOM
	if base == "" {
		t.Fatal("content without markup has no layer")
	}
	if Service(page("application/json", "bbbb"), nil).DOM == base {
		t.Error("changed content kept the layer")
	}
	if Service(page("text/plain", "aaaa"), nil).DOM == base {
		t.Error("changed content type kept the layer")
	}
	if got := Service(page("", ""), nil).DOM; got != "" {
		t.Errorf("layer = %q, want none when nothing stable is known about the body", got)
	}
}

func TestServiceLayersAreIndependent(t *testing.T) {
	base := Service(serviceObservation(), leafCert())

	obs := serviceObservation()
	obs.Headers.Values["server"] = "Apache"
	got := Service(obs, leafCert())

	if got.Headers == base.Headers {
		t.Fatal("headers layer did not change")
	}
	if got.TLS != base.TLS || got.Redirect != base.Redirect || got.DOM != base.DOM {
		t.Error("a header change leaked into another layer")
	}
	if got.Composite() == base.Composite() {
		t.Error("composite did not change with a layer")
	}
}

func TestUnobservedServiceHasNoLayers(t *testing.T) {
	l := Service(model.ServiceObservation{URL: "https://www.example.com:443", Error: "timeout"}, nil)
	if l != (Layers{}) {
		t.Errorf("layers = %+v, want none", l)
	}
}

// See TestCanonicalFormIsPinned.
func TestServiceCanonicalFormIsPinned(t *testing.T) {
	l := Service(serviceObservation(), leafCert())

	want := Layers{
		TLS:      "f509a007ad0379f70cddca487d28b4cfde8196c3d38a8a76212799d209b16d93",
		Headers:  "d384af0abd743669fec96b0a90656ae63d4c980e89663e3bc4c10e144bbaaf76",
		Redirect: "bc13c6ec9514e5a731ef28294030da891f65b227daae006ba3f702b53e9d3a96",
		DOM:      "7a529c1c1951861b70140e47b35de885d306f99d9a7dedcb17490faeaef389b4",
	}
	const wantComposite = "f2aa86546c9d10c21204cec559f22b7e11f0a90679df6ede35d6d043e50b717d"

	if l != want {
		t.Errorf("layers = %+v\nwant     %+v", l, want)
	}
	if got := l.Composite(); got != wantComposite {
		t.Errorf("composite = %s, want %s", got, wantComposite)
	}
}
