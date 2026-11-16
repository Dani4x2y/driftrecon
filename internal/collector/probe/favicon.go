package probe

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"math/bits"
	"net/http"
	"net/netip"
	"strings"
)

// favicon fetches an icon and returns its hash. Not having one is not an
// error: the result is then nil.
func (p *Prober) favicon(ctx context.Context, o origin, addrs []netip.Addr, target string) (*int32, error) {
	x, err := p.fetch(ctx, o, addrs, target)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	if x.status != http.StatusOK || len(x.body) == 0 || x.truncated || x.encoded || !isImage(x) {
		return nil, nil
	}
	hash := faviconHash(x.body)
	return &hash, nil
}

// isImage keeps the front page of a single-page application from being
// hashed as an icon: such applications answer every path with their HTML.
func isImage(x *exchange) bool {
	return strings.HasPrefix(mediaType(x.header.Get("Content-Type")), "image/") ||
		strings.HasPrefix(http.DetectContentType(x.body), "image/")
}

// faviconHash is the hash that internet-wide scan indexes file favicons
// under: MurmurHash3 of the file in base64, wrapped at 76 columns with a
// trailing newline, as a signed 32-bit number. Reproducing that exact form
// is what makes the value usable as a search term there.
func faviconHash(data []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(data)

	wrapped := make([]byte, 0, len(encoded)+len(encoded)/76+1)
	for len(encoded) > 0 {
		n := min(len(encoded), 76)
		wrapped = append(wrapped, encoded[:n]...)
		wrapped = append(wrapped, '\n')
		encoded = encoded[n:]
	}
	return int32(murmur3(wrapped, 0))
}

// murmur3 is the 32-bit variant of MurmurHash3 for x86.
func murmur3(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed

	blocks := len(data) / 4
	for i := range blocks {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2

		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}

	var k uint32
	tail := data[blocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}

	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
