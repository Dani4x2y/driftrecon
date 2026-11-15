package probe

import "testing"

func TestMurmur3(t *testing.T) {
	cases := []struct {
		data string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"", 0xffffffff, 0x81f16f39},
		{"\x00\x00\x00\x00", 0, 0x2362f9de},
		{"\xff\xff\xff\xff", 0, 0x76293b50},
		{"\x21\x43\x65\x87", 0, 0xf55b516b},
		{"\x21\x43\x65", 0, 0x7e4a8634},
		{"\x21\x43", 0, 0xa0f7b07a},
		{"\x21", 0, 0x72661cf4},
		{"test", 0, 0xba6bd213},
		{"Hello, world!", 0, 0xc0363e43},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2e4ff723},
		{"abc", 0x9747b28c, 0xc84a62dd},
		{"aaaa", 0x9747b28c, 0x5a97808a},
		{"Hello, world!", 0x9747b28c, 0x24884cba},
	}
	for _, tc := range cases {
		if got := murmur3([]byte(tc.data), tc.seed); got != tc.want {
			t.Errorf("murmur3(%q, %#x) = %#08x, want %#08x", tc.data, tc.seed, got, tc.want)
		}
	}
}

// The expected values were computed with Python's base64.encodebytes, whose
// line wrapping is part of the hash.
func TestFaviconHash(t *testing.T) {
	sequence := func(n, mod int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(i % mod)
		}
		return out
	}

	cases := []struct {
		name string
		data []byte
		want int32
	}{
		{"empty", nil, 0},
		{"one short line", []byte("hello"), 1155597304},
		{"exactly one line", sequence(57, 256), 459585070},
		{"one byte past a line", sequence(58, 256), -280317500},
		{"exactly two lines", sequence(114, 256), 1266597604},
		{"several lines", sequence(200, 256), -1874651529},
		{"with padding", sequence(1000, 251), -1514711491},
	}
	for _, tc := range cases {
		if got := faviconHash(tc.data); got != tc.want {
			t.Errorf("%s: hash = %d, want %d", tc.name, got, tc.want)
		}
	}
}
