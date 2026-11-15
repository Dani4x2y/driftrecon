package probe

import (
	"bytes"
	"cmp"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/net/html/charset"

	"github.com/Dani4x2y/driftrecon/internal/fingerprint"
	"github.com/Dani4x2y/driftrecon/internal/model"
)

const (
	maxTitleRunes = 200
	maxScripts    = 100
)

// describePage turns a response body into a page record. base is the URL the
// body was served from. The second result is the icon the document declares,
// if it declares one.
func describePage(x *exchange, base *url.URL, o origin) (*model.Page, *url.URL) {
	if len(x.body) == 0 {
		return nil, nil
	}
	contentType := x.header.Get("Content-Type")
	page := &model.Page{
		ContentType: mediaType(contentType),
		BodySHA256:  digest(x.body),
		Truncated:   x.truncated,
	}
	if x.encoded || !isHTML(page.ContentType, x.body) {
		return page, nil
	}

	doc, err := parseHTML(x.body, contentType)
	if err != nil {
		// The parser refuses documents nested deeper than it is willing to
		// follow. Such a body is kept as opaque content.
		return page, nil
	}

	structure := fingerprint.DOM(doc)
	page.Skeleton, page.SimHash = structure.Skeleton, &structure.SimHash

	d := document{base: base}
	d.scan(doc)

	page.Title = clip(d.title, maxTitleRunes)
	page.Generator = clip(d.generator, maxTitleRunes)
	for _, form := range d.forms {
		page.Forms = append(page.Forms, d.formSignature(form, o))
	}
	page.Scripts = d.scriptURLs()

	var icon *url.URL
	if d.icon != "" {
		if u, err := d.base.Parse(d.icon); err == nil {
			icon = u
		}
	}
	return page, icon
}

func mediaType(contentType string) string {
	if contentType == "" {
		return ""
	}
	if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
		return parsed
	}
	value, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(value))
}

func isHTML(mediaType string, body []byte) bool {
	switch mediaType {
	case "text/html", "application/xhtml+xml":
		return true
	case "":
		return strings.HasPrefix(http.DetectContentType(body), "text/html")
	}
	return false
}

func parseHTML(body []byte, contentType string) (*html.Node, error) {
	var r io.Reader = bytes.NewReader(body)
	// Without conversion a title in a legacy encoding would be stored as
	// mojibake. The structure is ASCII either way.
	if converted, err := charset.NewReader(bytes.NewReader(body), contentType); err == nil {
		r = converted
	}
	return html.Parse(r)
}

// document collects what a page declares about itself.
type document struct {
	base      *url.URL
	title     string
	generator string
	icon      string
	scripts   []string
	forms     []*html.Node
}

func (d *document) scan(doc *html.Node) {
	var hasTitle, hasBase bool
	for n := range doc.Descendants() {
		// Elements of embedded SVG and MathML live in a namespace of their
		// own, where a title is a tooltip and a script is not HTML.
		if n.Type != html.ElementNode || n.Namespace != "" {
			continue
		}
		switch n.DataAtom {
		case atom.Title:
			if !hasTitle {
				d.title, hasTitle = text(n), true
			}
		case atom.Base:
			if href := attr(n, "href"); href != "" && !hasBase {
				if u, err := d.base.Parse(href); err == nil {
					d.base, hasBase = u, true
				}
			}
		case atom.Meta:
			if d.generator == "" && strings.EqualFold(attr(n, "name"), "generator") {
				d.generator = attr(n, "content")
			}
		case atom.Link:
			if d.icon == "" && slices.Contains(strings.Fields(strings.ToLower(attr(n, "rel"))), "icon") {
				d.icon = attr(n, "href")
			}
		case atom.Script:
			if src := attr(n, "src"); src != "" {
				d.scripts = append(d.scripts, src)
			}
		case atom.Form:
			d.forms = append(d.forms, n)
		}
	}
}

func (d *document) scriptURLs() []string {
	var out []string
	seen := make(map[string]bool)
	for _, src := range d.scripts {
		u, err := d.base.Parse(strings.TrimSpace(src))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Fragment = ""
		s := u.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		if out = append(out, s); len(out) == maxScripts {
			break
		}
	}
	return out
}

// formSignature describes a form by where it submits to and which controls
// it has. Field values are left out: that is where anti-forgery tokens live.
func (d *document) formSignature(form *html.Node, o origin) model.Form {
	sig := model.Form{Method: strings.ToUpper(strings.TrimSpace(attr(form, "method")))}
	if sig.Method == "" {
		sig.Method = http.MethodGet
	}
	if action := strings.TrimSpace(attr(form, "action")); action != "" {
		if u, err := d.base.Parse(action); err == nil {
			sig.Action = formTarget(u, o)
		}
	}

	for n := range form.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		var field model.FormField
		switch n.DataAtom {
		case atom.Input:
			if field.Type = strings.ToLower(strings.TrimSpace(attr(n, "type"))); field.Type == "" {
				field.Type = "text"
			}
		case atom.Select:
			field.Type = "select"
		case atom.Textarea:
			field.Type = "textarea"
		default:
			continue
		}
		field.Name = maskIDs(attr(n, "name"), false)
		sig.Fields = append(sig.Fields, field)
	}
	slices.SortFunc(sig.Fields, func(a, b model.FormField) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Name, b.Name))
	})
	sig.Fields = slices.Compact(sig.Fields)
	return sig
}

// formTarget is the path a form submits to, or the full location when it
// leaves the service.
func formTarget(u *url.URL, o origin) string {
	if o.relation(u, nil) == model.RelSameOrigin {
		return pathPattern(u.EscapedPath())
	}
	target := *u
	target.RawQuery = ""
	return locationPattern(&target)
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val
		}
	}
	return ""
}

func text(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

// clip collapses whitespace and bounds the length of a string taken from a
// page.
func clip(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}
