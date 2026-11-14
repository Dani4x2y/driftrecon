package probe

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testHost = "www.example.test"

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

// newProber returns a prober that is allowed to talk to loopback servers
// and does not slow the tests down.
func newProber(t *testing.T, o Options) *Prober {
	t.Helper()
	if o.UserAgent == "" {
		o.UserAgent = "driftrecon-test"
	}
	if o.Timeout == 0 {
		o.Timeout = 3 * time.Second
	}
	if o.HostRate == 0 {
		o.HostRate = 10000
	}
	o.AllowPrivate = true
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// rawServer is a TCP server that answers each connection with whatever its
// handler writes. Unlike net/http it gives a test control over the exact
// bytes of a response.
type rawServer struct {
	port     uint16
	requests atomic.Int32
}

func (s *rawServer) origin(scheme string) origin {
	return origin{scheme: scheme, host: testHost, port: s.port}
}

// serveRaw starts a rawServer. The handler receives the parsed request, or
// nil when the client did not send one. With a TLS configuration the server
// closes connections without a close alert, as many real servers do.
func serveRaw(t *testing.T, conf *tls.Config, handler func(w io.Writer, r *http.Request)) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{port: uint16(ln.Addr().(*net.TCPAddr).Port)}

	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			tcp, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer tcp.Close()
				tcp.SetDeadline(time.Now().Add(10 * time.Second))

				var conn net.Conn = tcp
				if conf != nil {
					tc := tls.Server(tcp, conf)
					if tc.Handshake() != nil {
						return
					}
					conn = tc
				}
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					req = nil
				} else {
					s.requests.Add(1)
				}
				handler(conn, req)
			})
		}
	})
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	return s
}

// respond returns a handler that writes a fixed response.
func respond(response string) func(io.Writer, *http.Request) {
	return func(w io.Writer, _ *http.Request) {
		io.WriteString(w, response)
	}
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return port
}

// authority is a certificate that can sign others.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial atomic.Int64

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newAuthority creates a certificate authority, signed by parent or by
// itself when parent is nil.
func newAuthority(t *testing.T, name string, parent *authority) *authority {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Example Trust"}},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signer := &authority{cert: tmpl, key: key}
	if parent != nil {
		signer = parent
	}
	return &authority{cert: sign(t, tmpl, signer, key), key: key}
}

type leaf struct {
	names     []string
	notBefore time.Time
	notAfter  time.Time
	// chain lists the certificates sent after the leaf.
	chain []*authority
}

// issue creates a server certificate signed by a, or by its own key when a
// is nil.
func (a *authority) issue(t *testing.T, l leaf) tls.Certificate {
	t.Helper()
	if l.notBefore.IsZero() {
		l.notBefore = time.Now().Add(-time.Hour)
	}
	if l.notAfter.IsZero() {
		l.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: l.names[0]},
		DNSNames:     l.names,
		NotBefore:    l.notBefore,
		NotAfter:     l.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	signer := a
	if signer == nil {
		signer = &authority{cert: tmpl, key: key}
	}
	cert := sign(t, tmpl, signer, key)

	out := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	for _, c := range l.chain {
		out.Certificate = append(out.Certificate, c.cert.Raw)
	}
	return out
}

func sign(t *testing.T, tmpl *x509.Certificate, signer *authority, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pool(authorities ...*authority) *x509.CertPool {
	p := x509.NewCertPool()
	for _, a := range authorities {
		p.AddCert(a.cert)
	}
	return p
}
