package probe

import "testing"

func TestMaskIDsInValues(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"cloudflare":             "cloudflare",
		"gunicorn":               "gunicorn",
		"AmazonS3":               "AmazonS3",
		"nginx/1.24.0":           "nginx/1.24.0",
		"Apache/2.4.57 (Debian)": "Apache/2.4.57 (Debian)",
		"Microsoft-IIS/10.0":     "Microsoft-IIS/10.0",
		"PHP/8.2.10":             "PHP/8.2.10",
		// A build tag is not hexadecimal and too short to be a token.
		"Jetty(9.4.48.v20220622)": "Jetty(9.4.48.v20220622)",
		// Without a digit a hexadecimal string is more likely a word.
		"cafebabe": "cafebabe",

		"1.1 2e2c0e9ac1f3.cloudfront.net (CloudFront)": "1.1 *.cloudfront.net (CloudFront)",
		"web-7f3a9c2b1d": "web-*",
		"deadbeef01":     "*",
		"node 550e8400-e29b-41d4-a716-446655440000": "node *",
		"session_k3J9fLq82mZx0PaQwErT7":             "session_*",
	}
	for in, want := range cases {
		if got := maskIDs(in, false); got != want {
			t.Errorf("maskIDs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskIDsInPaths(t *testing.T) {
	cases := map[string]string{
		"orders":                               "orders",
		"v2":                                   "v2",
		"oauth2":                               "oauth2",
		"index.html":                           "index.html",
		"1042":                                 "*",
		"2026":                                 "*",
		"app.3f9a2c1b.js":                      "app.*.js",
		"report-2026-01-15.pdf":                "report-*-*-*.pdf",
		"(S(lit3py55t21z5v55vlm25s55))":        "(S(*))",
		"550E8400-E29B-41D4-A716-446655440000": "*",
	}
	for in, want := range cases {
		if got := maskIDs(in, true); got != want {
			t.Errorf("maskIDs(%q) = %q, want %q", in, got, want)
		}
	}
}
