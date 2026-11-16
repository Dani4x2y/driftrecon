package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// cipherSuites is everything the TLS stack implements, including suites it
// no longer offers by default. A probe has to be able to talk to a badly
// configured server in order to report it.
var cipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}()

func tlsConfig(host string, protocols ...string) *tls.Config {
	return &tls.Config{
		ServerName:   host,
		NextProtos:   protocols,
		MinVersion:   tls.VersionTLS10,
		CipherSuites: cipherSuites,
		// The probe inspects whatever certificate is presented, valid or
		// not, and sends nothing worth protecting. Trust is evaluated
		// separately and recorded as a finding.
		InsecureSkipVerify: true,
	}
}

// secure runs a TLS handshake over conn, which stays the caller's to close.
func secure(ctx context.Context, conn net.Conn, host string, protocols ...string) (*tls.Conn, error) {
	tc := tls.Client(conn, tlsConfig(host, protocols...))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fail(ReasonTLS, err)
	}
	return tc, nil
}

// handshake connects to an HTTPS service for the sole purpose of recording
// what the server negotiates and which certificates it presents. HTTP/2 is
// offered here, unlike in the requests that follow, so that the protocol the
// server prefers is on record. Errors follow the convention of get.
func (p *Prober) handshake(ctx context.Context, o origin, addrs []netip.Addr) (*model.TLS, []model.Certificate, error) {
	info, certs, err := p.negotiate(ctx, o, addrs)
	if err != nil && ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	return info, certs, err
}

func (p *Prober) negotiate(ctx context.Context, o origin, addrs []netip.Addr) (*model.TLS, []model.Certificate, error) {
	tcp, err := p.connect(ctx, o, addrs)
	if err != nil {
		return nil, nil, err
	}
	defer tcp.Close()

	stop := context.AfterFunc(ctx, func() { tcp.Close() })
	defer stop()
	tcp.SetDeadline(time.Now().Add(p.timeout))

	tc, err := secure(ctx, tcp, o.host, "h2", "http/1.1")
	if err != nil {
		return nil, nil, err
	}

	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fail(ReasonTLS, errors.New("no certificate presented"))
	}

	info := &model.TLS{
		Version: tls.VersionName(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
		ALPN:    state.NegotiatedProtocol,
		Issues:  p.trustIssues(state.PeerCertificates, o.host),
	}
	certs := make([]model.Certificate, len(state.PeerCertificates))
	for i, c := range state.PeerCertificates {
		certs[i] = summarize(c)
		info.Chain = append(info.Chain, certs[i].SHA256)
	}
	return info, certs, nil
}

// trustIssues evaluates the chain the way a browser would, except for the
// validity period, which is reported from the certificate dates instead.
func (p *Prober) trustIssues(chain []*x509.Certificate, host string) []string {
	leaf := chain[0]

	var issues []string
	if leaf.VerifyHostname(host) != nil {
		issues = append(issues, model.IssueHostnameMismatch)
	}
	switch {
	case selfSigned(leaf):
		issues = append(issues, model.IssueSelfSigned)
	case !p.chainsToRoot(chain):
		issues = append(issues, model.IssueUntrusted)
	}
	slices.Sort(issues)
	return issues
}

func (p *Prober) chainsToRoot(chain []*x509.Certificate) bool {
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	// Verification is pinned to a moment at which the leaf is valid. An
	// expired certificate then still reports whether its chain is sound,
	// and the finding does not flip when the expiry date passes.
	at := p.now()
	switch {
	case at.After(leaf.NotAfter):
		at = leaf.NotAfter
	case at.Before(leaf.NotBefore):
		at = leaf.NotBefore
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         p.roots,
		Intermediates: intermediates,
		CurrentTime:   at,
	})
	return err == nil
}

func selfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	// A signature made with an algorithm that is no longer accepted is
	// still the certificate's own.
	var insecure x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &insecure)
}

func summarize(c *x509.Certificate) model.Certificate {
	cert := model.Certificate{
		SHA256:     digest(c.Raw),
		SubjectCN:  c.Subject.CommonName,
		IssuerCN:   c.Issuer.CommonName,
		Serial:     c.SerialNumber.Text(16),
		SPKISHA256: digest(c.RawSubjectPublicKeyInfo),
		NotBefore:  c.NotBefore.UTC(),
		NotAfter:   c.NotAfter.UTC(),
		KeyAlg:     keyAlgorithm(c),
		IsCA:       c.IsCA,
		SelfSigned: selfSigned(c),
	}
	if len(c.Issuer.Organization) > 0 {
		cert.IssuerOrg = c.Issuer.Organization[0]
	}

	for _, name := range c.DNSNames {
		cert.SANs = append(cert.SANs, strings.ToLower(name))
	}
	for _, ip := range c.IPAddresses {
		cert.SANs = append(cert.SANs, ip.String())
	}
	slices.Sort(cert.SANs)
	cert.SANs = slices.Compact(cert.SANs)
	return cert
}

func keyAlgorithm(c *x509.Certificate) string {
	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + key.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
