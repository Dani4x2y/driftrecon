package probe

import (
	"crypto/tls"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func serverConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func handshake(t *testing.T, p *Prober, srv *rawServer) (*model.TLS, []model.Certificate) {
	t.Helper()
	info, certs, err := p.handshake(t.Context(), srv.origin("https"), loopback)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return info, certs
}

func TestHandshakeDescribesTheChain(t *testing.T) {
	root := newAuthority(t, "Example Root", nil)
	issuing := newAuthority(t, "Example Issuing CA", root)
	notBefore := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	cert := issuing.issue(t, leaf{
		names:     []string{testHost, "Example.TEST", "api.example.test"},
		notBefore: notBefore,
		notAfter:  notAfter,
		chain:     []*authority{issuing},
	})
	srv := serveRaw(t, serverConfig(cert), respond(""))

	info, certs := handshake(t, newProber(t, Options{Roots: pool(root)}), srv)

	if len(info.Issues) != 0 {
		t.Errorf("issues = %v, want none for a chain that leads to a trusted root", info.Issues)
	}
	if len(certs) != 2 || !slices.Equal(info.Chain, []string{certs[0].SHA256, certs[1].SHA256}) {
		t.Fatalf("chain = %v, certificates = %d", info.Chain, len(certs))
	}

	got := certs[0]
	want := model.Certificate{
		SHA256:     digest(cert.Leaf.Raw),
		SubjectCN:  testHost,
		IssuerCN:   "Example Issuing CA",
		IssuerOrg:  "Example Trust",
		Serial:     cert.Leaf.SerialNumber.Text(16),
		SANs:       []string{"api.example.test", "example.test", testHost},
		SPKISHA256: digest(cert.Leaf.RawSubjectPublicKeyInfo),
		NotBefore:  notBefore,
		NotAfter:   notAfter,
		KeyAlg:     "ECDSA-P-256",
	}
	if got.SHA256 != want.SHA256 || got.SubjectCN != want.SubjectCN || got.IssuerCN != want.IssuerCN ||
		got.IssuerOrg != want.IssuerOrg || got.Serial != want.Serial || !slices.Equal(got.SANs, want.SANs) ||
		got.SPKISHA256 != want.SPKISHA256 || !got.NotBefore.Equal(want.NotBefore) || !got.NotAfter.Equal(want.NotAfter) ||
		got.KeyAlg != want.KeyAlg || got.IsCA || got.SelfSigned {
		t.Errorf("leaf = %+v\nwant   %+v", got, want)
	}

	if ca := certs[1]; !ca.IsCA || ca.SelfSigned || ca.SubjectCN != "Example Issuing CA" || ca.IssuerCN != "Example Root" {
		t.Errorf("intermediate = %+v", ca)
	}
}

func TestHandshakeReportsTrustIssues(t *testing.T) {
	root := newAuthority(t, "Example Root", nil)
	issuing := newAuthority(t, "Example Issuing CA", root)
	stranger := newAuthority(t, "Unknown Root", nil)
	past := time.Now().Add(-48 * time.Hour)

	cases := []struct {
		name string
		cert tls.Certificate
		want []string
	}{
		{
			"issued directly by a trusted root",
			root.issue(t, leaf{names: []string{testHost}}),
			nil,
		},
		{
			"self-signed",
			(*authority)(nil).issue(t, leaf{names: []string{testHost}}),
			[]string{model.IssueSelfSigned},
		},
		{
			"unknown authority",
			stranger.issue(t, leaf{names: []string{testHost}, chain: []*authority{stranger}}),
			[]string{model.IssueUntrusted},
		},
		{
			"intermediate not sent",
			issuing.issue(t, leaf{names: []string{testHost}}),
			[]string{model.IssueUntrusted},
		},
		{
			"other host",
			root.issue(t, leaf{names: []string{"mail.example.test"}}),
			[]string{model.IssueHostnameMismatch},
		},
		{
			"wildcard for the parent domain",
			root.issue(t, leaf{names: []string{"*.example.test"}}),
			nil,
		},
		{
			"self-signed for another host",
			(*authority)(nil).issue(t, leaf{names: []string{"localhost"}}),
			[]string{model.IssueHostnameMismatch, model.IssueSelfSigned},
		},
		{
			// Expiry is derived from the dates when a report is made. The
			// chain of an expired certificate is still judged on its own.
			"expired but otherwise sound",
			root.issue(t, leaf{names: []string{testHost}, notBefore: past.Add(-24 * time.Hour), notAfter: past}),
			nil,
		},
		{
			"expired and from an unknown authority",
			stranger.issue(t, leaf{names: []string{testHost}, notBefore: past.Add(-24 * time.Hour), notAfter: past}),
			[]string{model.IssueUntrusted},
		},
		{
			"not valid yet",
			root.issue(t, leaf{names: []string{testHost}, notBefore: time.Now().Add(24 * time.Hour), notAfter: time.Now().Add(48 * time.Hour)}),
			nil,
		},
	}
	for _, tc := range cases {
		srv := serveRaw(t, serverConfig(tc.cert), respond(""))
		info, _ := handshake(t, newProber(t, Options{Roots: pool(root)}), srv)
		if !slices.Equal(info.Issues, tc.want) {
			t.Errorf("%s: issues = %v, want %v", tc.name, info.Issues, tc.want)
		}
	}
}

func TestHandshakeRecordsNegotiation(t *testing.T) {
	root := newAuthority(t, "Example Root", nil)
	cert := root.issue(t, leaf{names: []string{testHost}})

	modern := serverConfig(cert)
	modern.NextProtos = []string{"h2", "http/1.1"}

	legacy := serverConfig(cert)
	legacy.MaxVersion = tls.VersionTLS12
	legacy.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	cases := []struct {
		name string
		conf *tls.Config
		want model.TLS
	}{
		{"modern", modern, model.TLS{Version: "TLS 1.3", ALPN: "h2"}},
		{"legacy", legacy, model.TLS{Version: "TLS 1.2", Cipher: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}},
	}
	for _, tc := range cases {
		srv := serveRaw(t, tc.conf, respond(""))
		info, _ := handshake(t, newProber(t, Options{Roots: pool(root)}), srv)
		if info.Version != tc.want.Version || info.ALPN != tc.want.ALPN {
			t.Errorf("%s: version = %q, alpn = %q, want %q and %q", tc.name, info.Version, info.ALPN, tc.want.Version, tc.want.ALPN)
		}
		if info.Cipher == "" || (tc.want.Cipher != "" && info.Cipher != tc.want.Cipher) {
			t.Errorf("%s: cipher = %q, want %q", tc.name, info.Cipher, tc.want.Cipher)
		}
	}
}

func TestHandshakeFailure(t *testing.T) {
	// A plain HTTP server answers the ClientHello with something that is
	// not TLS.
	srv := serveRaw(t, nil, respond("HTTP/1.1 400 Bad Request\r\n\r\n"))

	_, _, err := newProber(t, Options{}).handshake(t.Context(), srv.origin("https"), loopback)
	wantFailure(t, err, ReasonTLS)

	o := origin{scheme: "https", host: testHost, port: closedPort(t)}
	_, _, err = newProber(t, Options{}).handshake(t.Context(), o, loopback)
	wantFailure(t, err, ReasonConnect)
}

func TestGetOverTLS(t *testing.T) {
	cert := (*authority)(nil).issue(t, leaf{names: []string{testHost}})
	var sni string
	conf := serverConfig(cert)
	conf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = hello.ServerName
		return nil, nil
	}
	srv := serveRaw(t, conf, func(w io.Writer, r *http.Request) {
		if r != nil {
			io.WriteString(w, "HTTP/1.1 200 OK\r\nServer: secure\r\n\r\nclosed without a close alert")
		}
	})

	x := get(t, newProber(t, Options{}), srv.origin("https"), "/")

	if x.status != 200 || string(x.body) != "closed without a close alert" {
		t.Errorf("status = %d, body = %q", x.status, x.body)
	}
	if x.leaf != digest(cert.Leaf.Raw) {
		t.Errorf("leaf = %s, want the digest of the server certificate", x.leaf)
	}
	if sni != testHost {
		t.Errorf("server name = %q, want %q", sni, testHost)
	}
}

func TestSummarizeKeyAlgorithms(t *testing.T) {
	root := newAuthority(t, "Example Root", nil)
	if got := summarize(root.cert); got.KeyAlg != "ECDSA-P-256" || !got.IsCA || !got.SelfSigned {
		t.Errorf("root = %+v", got)
	}
}
