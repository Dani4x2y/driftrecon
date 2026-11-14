package fingerprint

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func structure(t *testing.T, doc string) Structure {
	t.Helper()
	root, err := html.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return DOM(root)
}

// shop renders the landing page of a storefront. The options vary it the
// way real deployments of one application differ from each other.
type shop struct {
	products int
	promo    bool
	reviews  int
	toolbar  bool
	seed     int
}

func (s shop) html() string {
	var b strings.Builder
	fmt.Fprintf(&b, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Acme Store %d</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Clothing for release %d">
<link rel="stylesheet" href="/static/app.%d.css">
<link rel="icon" href="/favicon.ico">
<script src="/static/vendor.%d.js"></script>
<script src="/static/app.%d.js"></script>
</head>
<body class="home build-%d">
<!-- rendered by node %d -->
%s
<main>
`, s.seed, s.seed, s.seed, s.seed, s.seed, s.seed, s.seed, shopHeader)
	if s.promo {
		b.WriteString(`<section class="promo"><h2>Free shipping this week</h2><p>On all orders over 50.</p><a href="/sale">Shop the sale</a></section>
`)
	}
	b.WriteString(`<section class="hero"><h1>Autumn collection</h1><p>Layers for colder days.</p><a class="button" href="/new">Discover</a></section>
<section class="products"><h2>Popular right now</h2><div class="grid">
`)
	for i := range s.products {
		fmt.Fprintf(&b, `<article class="card" data-id="%d"><a href="/p/%d"><img src="/img/%d.jpg" alt=""><h3>Product %d</h3></a><p class="price"><span>%d.00</span></p><button type="button">Add to cart</button></article>
`, s.seed+i, s.seed+i, i, i, 20+i)
	}
	b.WriteString(`</div></section>
`)
	if s.reviews > 0 {
		b.WriteString(`<section class="reviews"><h2>What customers say</h2><div class="quotes">
`)
		for i := range s.reviews {
			fmt.Fprintf(&b, `<blockquote><p>Review text %d.</p><footer><cite>Customer %d</cite></footer></blockquote>
`, i, i)
		}
		b.WriteString(`</div></section>
`)
	}
	fmt.Fprintf(&b, `<section class="newsletter"><h2>Stay in the loop</h2><form action="/subscribe" method="post"><input type="hidden" name="csrf" value="token-%d"><input type="email" name="email"><button type="submit">Subscribe</button></form></section>
</main>
%s
`, s.seed, shopFooter)
	if s.toolbar {
		b.WriteString(`<div id="debug-toolbar"><ul><li><a href="#sql">SQL (14)</a></li><li><a href="#cache">Cache</a></li><li><a href="#log">Log</a></li></ul><div class="panel"><table><thead><tr><th>Query</th><th>Time</th></tr></thead><tbody><tr><td>SELECT 1</td><td>2 ms</td></tr><tr><td>SELECT 2</td><td>3 ms</td></tr></tbody></table><pre>trace</pre></div></div>
`)
	}
	b.WriteString(`</body>
</html>
`)
	return b.String()
}

const shopHeader = `<header class="site-header">
<a class="logo" href="/"><img src="/logo.png" alt="Acme"></a>
<nav><ul><li><a href="/new">New</a></li><li><a href="/men">Men</a></li><li><a href="/women">Women</a></li><li><a href="/sale">Sale</a></li></ul></nav>
<form action="/search" method="get"><input type="search" name="q"><button type="submit">Search</button></form>
<div class="account"><a href="/login">Sign in</a><a href="/cart"><span>Cart</span><span class="count">0</span></a></div>
</header>`

const shopFooter = `<footer>
<div class="columns">
<div><h4>Help</h4><ul><li><a href="/shipping">Shipping</a></li><li><a href="/returns">Returns</a></li><li><a href="/contact">Contact</a></li></ul></div>
<div><h4>Company</h4><ul><li><a href="/about">About</a></li><li><a href="/jobs">Jobs</a></li><li><a href="/press">Press</a></li></ul></div>
<div><h4>Legal</h4><ul><li><a href="/terms">Terms</a></li><li><a href="/privacy">Privacy</a></li></ul></div>
</div>
<p class="legal">Acme Ltd.</p>
</footer>`

// shopLogin is the sign-in page of the same storefront: the shell is shared,
// the main content is not.
const shopLogin = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/static/app.css">
<link rel="icon" href="/favicon.ico">
<script src="/static/vendor.js"></script>
<script src="/static/app.js"></script>
</head>
<body class="login">
` + shopHeader + `
<main>
<section class="auth"><h1>Sign in</h1>
<form action="/login" method="post"><input type="hidden" name="csrf" value="x"><label>Email<input type="email" name="email"></label><label>Password<input type="password" name="password"></label><label><input type="checkbox" name="remember">Remember me</label><button type="submit">Sign in</button></form>
<p><a href="/reset">Forgot your password?</a></p><p><a href="/register">Create an account</a></p>
</section>
</main>
` + shopFooter + `
</body>
</html>
`

// dashboard is an unrelated application.
const dashboard = `<!doctype html>
<html>
<head>
<title>Operations console</title>
<link rel="stylesheet" href="/assets/console.css">
<script src="/assets/console.js" defer></script>
</head>
<body>
<div id="app">
<aside class="sidebar"><h1>Console</h1><ul><li><a href="/jobs">Jobs</a></li><li><a href="/nodes">Nodes</a></li><li><a href="/queues">Queues</a></li><li><a href="/users">Users</a></li><li><a href="/settings">Settings</a></li></ul></aside>
<div class="content">
<div class="toolbar"><select name="env"><option>production</option><option>staging</option></select><button>Refresh</button><button>Export</button></div>
<table class="jobs"><thead><tr><th>Id</th><th>Name</th><th>State</th><th>Started</th><th>Owner</th></tr></thead>
<tbody><tr><td>1</td><td>backup</td><td>running</td><td>10:00</td><td>ops</td></tr><tr><td>2</td><td>reindex</td><td>queued</td><td>10:05</td><td>ops</td></tr><tr><td>3</td><td>report</td><td>failed</td><td>10:10</td><td>bi</td></tr></tbody></table>
<div class="pager"><button>Previous</button><span>1 of 12</span><button>Next</button></div>
<dl class="stats"><dt>Workers</dt><dd>12</dd><dt>Queued</dt><dd>40</dd><dt>Failed</dt><dd>3</dd></dl>
</div>
</div>
</body>
</html>
`

const nginxWelcome = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

func TestSkeletonIgnoresContent(t *testing.T) {
	a := structure(t, shop{products: 8, reviews: 3}.html())
	b := structure(t, shop{products: 8, reviews: 3, seed: 7}.html())
	if a.Skeleton == "" {
		t.Fatal("no skeleton for a document with elements")
	}
	if a != b {
		t.Errorf("text, comments and attribute values changed the structure:\n%+v\n%+v", a, b)
	}
}

func TestSkeletonCollapsesRepeatedSiblings(t *testing.T) {
	base := structure(t, shop{products: 8, reviews: 3}.html())
	for _, n := range []int{2, 24, 200} {
		got := structure(t, shop{products: n, reviews: 5}.html())
		if got != base {
			t.Errorf("%d products: structure differs from a page with 8", n)
		}
	}

	// One item and several are told apart exactly, but remain the same page
	// as far as similarity goes.
	single := structure(t, shop{products: 1, reviews: 3}.html())
	if single.Skeleton == base.Skeleton {
		t.Error("a single item must not read as a repeated one")
	}
	if d := Distance(single.SimHash, base.SimHash); d != 0 {
		t.Errorf("a single item moved the simhash by %d bits", d)
	}
}

func TestSkeletonTellsDifferentShapesApart(t *testing.T) {
	const list = `<ul><li><a>1</a></li><li><a>2</a></li></ul>`
	base := structure(t, list)

	changed := map[string]string{
		"deeper item":     `<ul><li><a><b>1</b></a></li><li><a><b>2</b></a></li></ul>`,
		"other tag":       `<ol><li><a>1</a></li><li><a>2</a></li></ol>`,
		"odd one out":     `<ul><li><a>1</a></li><li><span>2</span></li></ul>`,
		"extra sibling":   `<ul><li><a>1</a></li><li><a>2</a></li></ul><p>note</p>`,
		"moved into item": `<ul><li><a>1</a><ul><li><a>2</a></li></ul></li></ul>`,
	}
	for name, doc := range changed {
		if structure(t, doc).Skeleton == base.Skeleton {
			t.Errorf("%s: skeleton did not change", name)
		}
	}

	// A run is only collapsed while it is uninterrupted.
	a := structure(t, `<p>1</p><p>2</p><hr><p>3</p>`)
	b := structure(t, `<p>1</p><hr><p>2</p><p>3</p>`)
	if a.Skeleton == b.Skeleton {
		t.Error("the position of a run within its siblings was lost")
	}
}

func TestVectorGraphicsAreOpaque(t *testing.T) {
	a := structure(t, `<a href="/"><svg viewBox="0 0 10 10"><path d="M0 0"/></svg></a>`)
	b := structure(t, `<a href="/"><svg viewBox="0 0 24 24"><g><circle r="4"/><path d="M1 1"/><path d="M2 2"/></g></svg></a>`)
	if a != b {
		t.Error("the inside of an inline drawing changed the structure")
	}
	if a.Skeleton == structure(t, `<a href="/"></a>`).Skeleton {
		t.Error("the drawing itself must still count as an element")
	}
}

// The thresholds are starting points measured on these fixtures: variations
// of one page stay within SimilarStructure, another page of the same
// application lands just outside of it, and unrelated applications are far
// away. They are expected to be revisited with real-world data.
func TestSimHashBands(t *testing.T) {
	page := shop{products: 8, reviews: 3}
	base := structure(t, page.html())

	variant := func(change func(*shop)) string {
		s := page
		change(&s)
		return s.html()
	}
	cases := []struct {
		name     string
		doc      string
		min, max int
	}{
		{"promo banner added", variant(func(s *shop) { s.promo = true }), 1, SameStructure},
		{"reviews section removed", variant(func(s *shop) { s.reviews = 0 }), 1, SameStructure},
		{"debug toolbar injected", variant(func(s *shop) { s.toolbar = true }), 1, SameStructure},
		{"several changes at once", variant(func(s *shop) { s.promo, s.toolbar, s.products = true, true, 12 }), SameStructure + 1, SimilarStructure},
		{"other page, same application", shopLogin, SimilarStructure + 1, 2 * SimilarStructure},
		{"unrelated application", dashboard, 2*SimilarStructure + 1, 64},
		{"default server page", nginxWelcome, 2*SimilarStructure + 1, 64},
	}
	for _, tc := range cases {
		got := structure(t, tc.doc)
		if got.Skeleton == base.Skeleton {
			t.Errorf("%s: skeleton did not change", tc.name)
		}
		if d := Distance(base.SimHash, got.SimHash); d < tc.min || d > tc.max {
			t.Errorf("%s: distance = %d, want %d..%d", tc.name, d, tc.min, tc.max)
		}
	}

	if d := Distance(structure(t, dashboard).SimHash, structure(t, nginxWelcome).SimHash); d <= 2*SimilarStructure {
		t.Errorf("unrelated documents are only %d bits apart", d)
	}
}

func TestDocumentsAreCutOffDeterministically(t *testing.T) {
	// Alternating tags keep siblings from collapsing, so every element
	// counts towards the limit.
	filler := strings.Repeat("<i></i><b></b>", maxDOMNodes/2+500)

	a := structure(t, filler+"<form><input></form>")
	b := structure(t, filler+"<table><tr><td></td></tr></table>")
	if a != b {
		t.Error("elements past the node limit influenced the structure")
	}
	if c := structure(t, "<form><input></form>"+filler); c.Skeleton == a.Skeleton {
		t.Error("elements before the node limit were ignored")
	}
}

func TestEmptyDocumentHasNoStructure(t *testing.T) {
	if got := DOM(&html.Node{Type: html.DocumentNode}); got != (Structure{}) {
		t.Errorf("structure of an empty tree = %+v", got)
	}

	// The parser supplies the html, head and body elements on its own.
	if got := structure(t, ""); got.Skeleton == "" {
		t.Error("a parsed document always has a skeleton")
	}
}

func TestDistance(t *testing.T) {
	cases := []struct {
		a, b uint64
		want int
	}{
		{0, 0, 0},
		{0xffffffffffffffff, 0, 64},
		{0b1011, 0b0001, 2},
		{1 << 63, 0, 1},
	}
	for _, tc := range cases {
		if got := Distance(model.SimHash(tc.a), model.SimHash(tc.b)); got != tc.want {
			t.Errorf("Distance(%#x, %#x) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
