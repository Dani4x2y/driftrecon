package probe

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	// maxHeadBytes bounds the status line and headers of a response.
	maxHeadBytes = 64 << 10
	// maxInformational is how many 1xx responses may precede the final one.
	maxInformational = 5
	// maxBackoff is the longest pause a server can ask for and still be
	// asked again within the same scan.
	maxBackoff = 10 * time.Second

	accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)

// exchange is one request and the response to it.
type exchange struct {
	status int
	// fields are the response headers exactly as sent: original spelling,
	// original order, repeated names included.
	fields []headerField
	header http.Header
	// body is the decoded response body, cut off at the size limit. It is
	// not read for redirects.
	body      []byte
	truncated bool
	// encoded marks a body in a content encoding that was not asked for and
	// could not be undone.
	encoded bool
	// leaf is the SHA-256 of the server certificate, for HTTPS.
	leaf string
}

type headerField struct {
	name, value string
}

// redirects reports whether the response sends the client elsewhere.
func (x *exchange) redirects() bool {
	switch x.status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return x.header.Get("Location") != ""
	}
	return false
}

// fetch requests target and honours a server that asks to be left alone for
// a moment: it slows down for the rest of the scan and repeats the request
// once, unless the pause asked for is too long to sit out.
func (p *Prober) fetch(ctx context.Context, o origin, addrs []netip.Addr, target string) (*exchange, error) {
	x, err := p.get(ctx, o, addrs, target)
	if err != nil {
		return nil, err
	}
	pause, ok := backoff(x, p.now())
	if !ok {
		return x, nil
	}
	p.slowDown(o.host)
	if pause > maxBackoff {
		return x, nil
	}

	timer := time.NewTimer(pause)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return p.get(ctx, o, addrs, target)
}

// backoff returns how long the server wants the client to stay away, if the
// response is a request to back off at all.
func backoff(x *exchange, now time.Time) (time.Duration, bool) {
	after := x.header.Get("Retry-After")
	switch {
	case x.status == http.StatusTooManyRequests:
	case x.status == http.StatusServiceUnavailable && after != "":
	default:
		return 0, false
	}

	if secs, err := strconv.Atoi(strings.TrimSpace(after)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(after); err == nil {
		return max(0, at.Sub(now)), true
	}
	return time.Second, true
}

// get performs a single GET over a connection of its own. An error is
// either the context's, which ends the scan, or a failure, which describes
// the service.
func (p *Prober) get(ctx context.Context, o origin, addrs []netip.Addr, target string) (*exchange, error) {
	x, err := p.roundTrip(ctx, o, addrs, target)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return x, err
}

// roundTrip lets net/http parse the response while keeping the bytes it was
// parsed from on the side: a parsed header is a map and has lost the order
// and spelling in which the server wrote the fields.
func (p *Prober) roundTrip(ctx context.Context, o origin, addrs []netip.Addr, target string) (*exchange, error) {
	tcp, err := p.connect(ctx, o, addrs)
	if err != nil {
		return nil, err
	}
	defer tcp.Close()

	// A cancelled scan must not sit out the timeout of a request in flight.
	stop := context.AfterFunc(ctx, func() { tcp.Close() })
	defer stop()
	tcp.SetDeadline(time.Now().Add(p.timeout))

	var (
		x    = &exchange{}
		conn = tcp
	)
	if o.secure() {
		tc, err := secure(ctx, tcp, o.host, "http/1.1")
		if err != nil {
			return nil, err
		}
		conn = tc
		if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
			x.leaf = digest(certs[0].Raw)
		}
	}

	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: %s\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
		target, o.authority(), p.userAgent, accept)
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, fail(ReasonConnect, err)
	}

	rec := &recorder{r: conn}
	resp, err := readResponse(bufio.NewReader(rec))
	if err != nil {
		return nil, fail(ReasonProtocol, err)
	}
	defer resp.Body.Close()

	x.status = resp.StatusCode
	x.header = resp.Header
	if x.fields, err = finalHead(rec.stop()); err != nil {
		return nil, fail(ReasonProtocol, err)
	}
	if x.redirects() {
		return x, nil
	}

	tcp.SetDeadline(time.Now().Add(p.timeout))
	if x.body, x.truncated, x.encoded, err = readBody(resp, p.maxBody); err != nil {
		return nil, fail(ReasonProtocol, err)
	}
	return x, nil
}

// readResponse reads up to the first response that is not informational.
func readResponse(r *bufio.Reader) (*http.Response, error) {
	for range maxInformational + 1 {
		resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodGet})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
	}
	return nil, errors.New("too many informational responses")
}

// readBody reads at most limit bytes of the body and undoes gzip encoding.
// A body in any other encoding is returned as it is and reported as encoded.
func readBody(resp *http.Response, limit int64) (body []byte, truncated, encoded bool, err error) {
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		// A body without a declared length ends when the server closes the
		// connection, and many servers do that without a TLS close alert.
		// That is the regular end of such a body, not a failure.
		unframed := resp.ContentLength < 0 && len(resp.TransferEncoding) == 0
		if !unframed || !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, false, err
		}
	}
	if int64(len(body)) > limit {
		body, truncated = body[:limit], true
	}

	switch encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); encoding {
	case "", "identity":
		return body, truncated, false, nil
	case "gzip", "x-gzip":
	default:
		return body, truncated, true, nil
	}

	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false, false, err
	}
	plain, err := io.ReadAll(io.LimitReader(zr, limit+1))
	// A compressed stream that was cut off still inflates to a valid prefix.
	if err != nil && (!truncated || !errors.Is(err, io.ErrUnexpectedEOF)) {
		return nil, false, false, err
	}
	if int64(len(plain)) > limit {
		plain, truncated = plain[:limit], true
	}
	return plain, truncated, false, nil
}

// recorder keeps a copy of everything read through it until it is stopped.
type recorder struct {
	r       io.Reader
	buf     []byte
	stopped bool
}

func (rec *recorder) Read(p []byte) (int, error) {
	n, err := rec.r.Read(p)
	if !rec.stopped && n > 0 {
		rec.buf = append(rec.buf, p[:n]...)
		// The parser reading through the recorder does not bound the size
		// of a header block on its own.
		if len(rec.buf) > maxHeadBytes {
			return n, errors.New("response header too large")
		}
	}
	return n, err
}

func (rec *recorder) stop() []byte {
	rec.stopped = true
	return rec.buf
}

// finalHead extracts the header fields of the final response from the start
// of a response stream, skipping informational responses before it.
func finalHead(stream []byte) ([]headerField, error) {
	for range maxInformational + 1 {
		status, fields, rest, ok := splitHead(stream)
		if !ok {
			break
		}
		if status >= 200 || status == http.StatusSwitchingProtocols {
			return fields, nil
		}
		stream = rest
	}
	return nil, errors.New("response header not found")
}

// splitHead parses one status line and header block. Like the parser it
// shadows, it accepts bare line feeds as line endings.
func splitHead(stream []byte) (status int, fields []headerField, rest []byte, ok bool) {
	line, rest, found := cutLine(stream)
	if !found {
		return 0, nil, nil, false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, nil, nil, false
	}
	if status, _ = strconv.Atoi(parts[1]); status == 0 {
		return 0, nil, nil, false
	}

	for {
		line, rest, found = cutLine(rest)
		switch {
		case !found:
			return 0, nil, nil, false
		case line == "":
			return status, fields, rest, true
		case line[0] == ' ' || line[0] == '\t':
			// A continuation line belongs to the field before it.
			if n := len(fields); n > 0 {
				fields[n-1].value += " " + strings.TrimSpace(line)
			}
		default:
			name, value, hasColon := strings.Cut(line, ":")
			if hasColon && name != "" {
				fields = append(fields, headerField{name: name, value: strings.TrimSpace(value)})
			}
		}
	}
}

func cutLine(data []byte) (line string, rest []byte, ok bool) {
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return "", nil, false
	}
	return string(bytes.TrimSuffix(data[:i], []byte{'\r'})), data[i+1:], true
}
