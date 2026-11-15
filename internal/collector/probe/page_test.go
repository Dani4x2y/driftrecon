package probe

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

var pageOrigin = origin{scheme: "https", host: "www.example.test", port: 443}

// describe parses body as the response to a request for at.
func describe(t *testing.T, contentType, at, body string) (*model.Page, string) {
	t.Helper()
	head := "HTTP/1.1 200 OK\r\n"
	if contentType != "" {
		head += "Content-Type: " + contentType + "\r\n"
	}
	x := parseExchange(t, fmt.Sprintf("%sContent-Length: %d\r\n\r\n%s", head, len(body), body))

	page, icon := describePage(x, mustParse(t, at), pageOrigin)
	if icon == nil {
		return page, ""
	}
	return page, icon.String()
}

const loginPage = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>
   Sign in &amp; continue
</title>
<meta name="Generator" content="  WordPress 6.4.2 ">
<meta name="generator" content="ignored second generator">
<link rel="stylesheet" href="/static/app.css">
<link rel="apple-touch-icon" href="/touch.png">
<link rel="shortcut ICON" href="/static/favicon.png?v=3">
<link rel="icon" href="/second.ico">
<script src="/static/vendor.js"></script>
<script src="app.js#main"></script>
<script>inline()</script>
<script src="https://cdn.example.org/lib.js?v=1"></script>
<script src="/static/vendor.js"></script>
<script src="data:text/javascript,alert(1)"></script>
<script src="//analytics.example.net/t.js"></script>
</head>
<body>
<svg><title>Logo</title><script href="x.js"></script></svg>
<form action="/session" method="post">
  <input type="hidden" name="csrf_token" value="b1946ac92492d2347c6235b4d2611184">
  <input name="username">
  <input type="PASSWORD" name="password">
  <input type="checkbox" name="remember">
  <input type="checkbox" name="remember">
  <select name="realm"><option>staff</option><option>partner</option></select>
  <textarea name="note"></textarea>
  <button type="submit" name="go">Sign in</button>
</form>
<form>
  <input type="search" name="q">
</form>
<form action="https://sso.example.org/saml?RelayState=abc" method="POST"></form>
<form action="search/results;jsessionid=A1B2C3D4E5F6A7B8?q=1" method="get"></form>
<title>not the title</title>
</body>
</html>`

func TestDescribePage(t *testing.T) {
	page, icon := describe(t, "text/html; charset=UTF-8", "https://www.example.test/account/login?next=%2F", loginPage)

	if page.ContentType != "text/html" {
		t.Errorf("content type = %q", page.ContentType)
	}
	if page.Title != "Sign in & continue" {
		t.Errorf("title = %q", page.Title)
	}
	if page.Generator != "WordPress 6.4.2" {
		t.Errorf("generator = %q", page.Generator)
	}
	if page.Skeleton == "" || page.SimHash == nil {
		t.Errorf("skeleton = %q, simhash = %v, want both for a document", page.Skeleton, page.SimHash)
	}
	if page.BodySHA256 != digest([]byte(loginPage)) || page.Truncated {
		t.Errorf("body digest = %s, truncated = %v", page.BodySHA256, page.Truncated)
	}

	wantScripts := []string{
		"https://www.example.test/static/vendor.js",
		"https://www.example.test/account/app.js",
		"https://cdn.example.org/lib.js?v=1",
		"https://analytics.example.net/t.js",
	}
	if !slices.Equal(page.Scripts, wantScripts) {
		t.Errorf("scripts = %q\nwant      %q", page.Scripts, wantScripts)
	}

	wantForms := []model.Form{
		{Method: "POST", Action: "/session", Fields: []model.FormField{
			{Type: "checkbox", Name: "remember"},
			{Type: "hidden", Name: "csrf_token"},
			{Type: "password", Name: "password"},
			{Type: "select", Name: "realm"},
			{Type: "text", Name: "username"},
			{Type: "textarea", Name: "note"},
		}},
		{Method: "GET", Fields: []model.FormField{{Type: "search", Name: "q"}}},
		{Method: "POST", Action: "https://sso.example.org/saml"},
		{Method: "GET", Action: "/account/search/results"},
	}
	if !slices.EqualFunc(page.Forms, wantForms, equalForms) {
		t.Errorf("forms = %+v\nwant    %+v", page.Forms, wantForms)
	}
	if !page.Forms[0].HasPassword() || page.Forms[1].HasPassword() {
		t.Error("the login form was not told apart from the search form")
	}

	if want := "https://www.example.test/static/favicon.png?v=3"; icon != want {
		t.Errorf("icon = %q, want %q", icon, want)
	}
}

func TestDescribePageHonoursBaseElement(t *testing.T) {
	page, icon := describe(t, "text/html", "https://www.example.test/deep/path/", `<html><head>
<script src="early.js"></script>
<base href="/assets/">
<base href="/ignored/">
<link rel="icon" href="fav.ico">
<script src="app.js"></script>
</head><body><form action="submit"></form></body></html>`)

	// The base applies to the whole document, including what precedes it.
	want := []string{"https://www.example.test/assets/early.js", "https://www.example.test/assets/app.js"}
	if !slices.Equal(page.Scripts, want) {
		t.Errorf("scripts = %q, want %q", page.Scripts, want)
	}
	if got := page.Forms[0].Action; got != "/assets/submit" {
		t.Errorf("form action = %q", got)
	}
	if icon != "https://www.example.test/assets/fav.ico" {
		t.Errorf("icon = %q", icon)
	}
}

func TestDescribePageBoundsWhatItKeeps(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("<title>" + strings.Repeat("ż", 500) + "</title>")
	for i := range 250 {
		fmt.Fprintf(&doc, `<script src="/js/chunk-%d.js"></script>`, i)
	}
	page, _ := describe(t, "text/html", "https://www.example.test/", doc.String())

	if got := []rune(page.Title); len(got) != maxTitleRunes || got[0] != 'ż' {
		t.Errorf("title has %d runes, want %d whole ones", len(got), maxTitleRunes)
	}
	if len(page.Scripts) != maxScripts {
		t.Errorf("scripts = %d, want the first %d", len(page.Scripts), maxScripts)
	}
}

func TestDescribePageDecodesLegacyCharsets(t *testing.T) {
	// "Zażółć gęślą jaźń" in ISO 8859-2.
	const title = "Za\xbf\xf3\xb3\xe6 g\xea\xb6l\xb1 ja\xbc\xf1"

	fromHeader, _ := describe(t, "text/html; charset=iso-8859-2", "https://www.example.test/", "<title>"+title+"</title>")
	if fromHeader.Title != "Zażółć gęślą jaźń" {
		t.Errorf("title = %q with the charset in the header", fromHeader.Title)
	}

	fromMeta, _ := describe(t, "text/html", "https://www.example.test/", `<meta charset="iso-8859-2"><title>`+title+"</title>")
	if fromMeta.Title != "Zażółć gęślą jaźń" {
		t.Errorf("title = %q with the charset in the document", fromMeta.Title)
	}
}

func TestDescribePageWithoutMarkup(t *testing.T) {
	const body = `{"status":"ok","version":"1.4.2"}`
	page, icon := describe(t, "application/json; charset=utf-8", "https://www.example.test/", body)

	want := model.Page{ContentType: "application/json", BodySHA256: digest([]byte(body))}
	if page.ContentType != want.ContentType || page.BodySHA256 != want.BodySHA256 ||
		page.Skeleton != "" || page.SimHash != nil || page.Title != "" || page.Forms != nil || page.Scripts != nil {
		t.Errorf("page = %+v, want %+v", page, want)
	}
	if icon != "" {
		t.Errorf("icon = %q", icon)
	}

	// Markup is not looked for in a body that declares itself as something
	// else.
	text, _ := describe(t, "text/plain", "https://www.example.test/", "<title>readme</title>")
	if text.Skeleton != "" || text.Title != "" {
		t.Errorf("a text/plain body was parsed as a document: %+v", text)
	}
}

func TestDescribePageSniffsUndeclaredContent(t *testing.T) {
	doc, _ := describe(t, "", "https://www.example.test/", "<!DOCTYPE html><title>undeclared</title>")
	if doc.Title != "undeclared" || doc.Skeleton == "" || doc.ContentType != "" {
		t.Errorf("page = %+v, want the markup to be recognised", doc)
	}

	data, _ := describe(t, "", "https://www.example.test/", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	if data.Skeleton != "" || data.BodySHA256 == "" {
		t.Errorf("page = %+v, want opaque content", data)
	}
}

func TestDescribePageKeepsUnparsableDocumentsOpaque(t *testing.T) {
	deep := strings.Repeat("<div>", 600) + "<form><input type=password name=p></form>"
	page, _ := describe(t, "text/html", "https://www.example.test/", deep)

	if page.Skeleton != "" || page.SimHash != nil || page.Forms != nil {
		t.Errorf("page = %+v, want no structure for a document the parser rejects", page)
	}
	if page.ContentType != "text/html" || page.BodySHA256 != digest([]byte(deep)) {
		t.Errorf("page = %+v, want it kept as content", page)
	}
}

func TestDescribePageWithoutUsableBody(t *testing.T) {
	x := parseExchange(t, "HTTP/1.1 204 No Content\r\nContent-Type: text/html\r\n\r\n")
	if page, _ := describePage(x, mustParse(t, "https://www.example.test/"), pageOrigin); page != nil {
		t.Errorf("page = %+v, want none without a body", page)
	}

	x = parseExchange(t, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\n\x0b\x01\x80\x03")
	x.encoded = true
	page, _ := describePage(x, mustParse(t, "https://www.example.test/"), pageOrigin)
	if page == nil || page.Skeleton != "" || page.BodySHA256 == "" {
		t.Errorf("page = %+v, want an encoded body kept as opaque content", page)
	}

	x = parseExchange(t, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<title>cut</title><p")
	x.truncated = true
	page, _ = describePage(x, mustParse(t, "https://www.example.test/"), pageOrigin)
	if page == nil || !page.Truncated || page.Title != "cut" {
		t.Errorf("page = %+v, want the part that was read to be described", page)
	}
}

func TestMediaType(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"text/html":                      "text/html",
		"Text/HTML; Charset=UTF-8":       "text/html",
		"application/json;charset=utf-8": "application/json",
		"text/html; charset":             "text/html",
		"image/x-icon":                   "image/x-icon",
	}
	for in, want := range cases {
		if got := mediaType(in); got != want {
			t.Errorf("mediaType(%q) = %q, want %q", in, got, want)
		}
	}
}
