package probe

import (
	"maps"
	"slices"
	"testing"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func sampleObservation() model.ServiceObservation {
	simhash := model.SimHash(0x1111)
	return model.ServiceObservation{
		Hops: []model.Hop{
			{Status: 302, Location: "https://www.example.test/home", Relation: model.RelSameOrigin},
			{Status: 200},
		},
		Headers: &model.Headers{
			Names: []string{"Server", "Date", "Content-Type", "Set-Cookie", "X-Frame-Options"},
			Values: map[string]string{
				"server":          "nginx",
				"x-frame-options": "DENY",
			},
			Cookies: []model.Cookie{
				{Name: "session", Flags: []string{"httponly", "secure"}},
				{Name: "lang"},
			},
		},
		Page: &model.Page{
			ContentType: "text/html",
			Title:       "Home",
			Generator:   "Hugo",
			Skeleton:    "aaaa",
			SimHash:     &simhash,
			Forms:       []model.Form{{Method: "GET", Action: "/search", Fields: []model.FormField{{Type: "search", Name: "q"}}}},
			Scripts:     []string{"https://www.example.test/a.js", "https://www.example.test/b.js"},
			BodySHA256:  "bbbb",
		},
	}
}

func TestMergeOfEqualSamplesChangesNothing(t *testing.T) {
	got := merge(sampleObservation(), sampleObservation())
	want := sampleObservation()

	if len(got.Volatile) != 0 {
		t.Errorf("volatile = %v, want nothing", got.Volatile)
	}
	if !slices.Equal(got.Hops, want.Hops) {
		t.Errorf("hops = %+v", got.Hops)
	}
	if !slices.Equal(got.Headers.Names, want.Headers.Names) || !maps.Equal(got.Headers.Values, want.Headers.Values) ||
		len(got.Headers.Cookies) != 2 {
		t.Errorf("headers = %+v", got.Headers)
	}
	p, q := got.Page, want.Page
	if p.ContentType != q.ContentType || p.Title != q.Title || p.Generator != q.Generator || p.Skeleton != q.Skeleton ||
		*p.SimHash != *q.SimHash || p.BodySHA256 != q.BodySHA256 || !slices.Equal(p.Scripts, q.Scripts) ||
		!slices.EqualFunc(p.Forms, q.Forms, equalForms) {
		t.Errorf("page = %+v", p)
	}
}

func TestMergeMasksWhatDiffers(t *testing.T) {
	type check func(t *testing.T, got model.ServiceObservation)

	cases := []struct {
		name     string
		change   func(o *model.ServiceObservation)
		volatile []string
		check    check
	}{
		{
			"redirect target",
			func(o *model.ServiceObservation) { o.Hops[0].Location = "https://www.example.test/start" },
			[]string{"redirect"},
			func(t *testing.T, got model.ServiceObservation) {
				if got.Hops != nil {
					t.Errorf("hops = %+v, want none", got.Hops)
				}
			},
		},
		{
			"final status",
			func(o *model.ServiceObservation) { o.Hops[1].Status = 503 },
			[]string{"redirect"},
			nil,
		},
		{
			"header only in one sample",
			func(o *model.ServiceObservation) {
				o.Headers.Names = []string{"Server", "Date", "X-Cache", "Content-Type", "Set-Cookie", "X-Frame-Options"}
			},
			[]string{"header:x-cache"},
			func(t *testing.T, got model.ServiceObservation) {
				want := []string{"Server", "Date", "Content-Type", "Set-Cookie", "X-Frame-Options"}
				if !slices.Equal(got.Headers.Names, want) {
					t.Errorf("names = %q, want %q in the original order", got.Headers.Names, want)
				}
			},
		},
		{
			"header order",
			func(o *model.ServiceObservation) {
				o.Headers.Names = []string{"Date", "Server", "Content-Type", "Set-Cookie", "X-Frame-Options"}
			},
			[]string{"header-order"},
			func(t *testing.T, got model.ServiceObservation) {
				want := []string{"Content-Type", "Date", "Server", "Set-Cookie", "X-Frame-Options"}
				if !slices.Equal(got.Headers.Names, want) {
					t.Errorf("names = %q, want them sorted", got.Headers.Names)
				}
			},
		},
		{
			"header spelling",
			func(o *model.ServiceObservation) { o.Headers.Names[0] = "server" },
			[]string{"header:server"},
			func(t *testing.T, got model.ServiceObservation) {
				if slices.Contains(got.Headers.Names, "Server") || slices.Contains(got.Headers.Names, "server") {
					t.Errorf("names = %q", got.Headers.Names)
				}
			},
		},
		{
			"server banner",
			func(o *model.ServiceObservation) { o.Headers.Values["server"] = "Apache" },
			[]string{"value:server"},
			func(t *testing.T, got model.ServiceObservation) {
				if want := map[string]string{"x-frame-options": "DENY"}; !maps.Equal(got.Headers.Values, want) {
					t.Errorf("values = %v, want %v", got.Headers.Values, want)
				}
			},
		},
		{
			"policy only in one sample",
			func(o *model.ServiceObservation) { o.Headers.Values["strict-transport-security"] = "max-age=1" },
			[]string{"value:strict-transport-security"},
			nil,
		},
		{
			"cookie flags",
			func(o *model.ServiceObservation) { o.Headers.Cookies[0].Flags = []string{"httponly"} },
			[]string{"cookie:session"},
			func(t *testing.T, got model.ServiceObservation) {
				if len(got.Headers.Cookies) != 1 || got.Headers.Cookies[0].Name != "lang" {
					t.Errorf("cookies = %+v", got.Headers.Cookies)
				}
			},
		},
		{
			"cookie only in one sample",
			func(o *model.ServiceObservation) {
				o.Headers.Cookies = append(o.Headers.Cookies, model.Cookie{Name: "ab_test"})
			},
			[]string{"cookie:ab_test"},
			nil,
		},
		{
			"title",
			func(o *model.ServiceObservation) { o.Page.Title = "Home (3)" },
			[]string{"title"},
			func(t *testing.T, got model.ServiceObservation) {
				if got.Page.Title != "" || got.Page.Skeleton != "aaaa" {
					t.Errorf("page = %+v", got.Page)
				}
			},
		},
		{
			"structure",
			func(o *model.ServiceObservation) {
				other := model.SimHash(0x2222)
				o.Page.Skeleton, o.Page.SimHash, o.Page.BodySHA256 = "cccc", &other, "dddd"
			},
			[]string{"body", "dom"},
			func(t *testing.T, got model.ServiceObservation) {
				if got.Page.Skeleton != "" || got.Page.BodySHA256 != "" {
					t.Errorf("page = %+v, want the unstable hashes dropped", got.Page)
				}
				if got.Page.SimHash == nil || *got.Page.SimHash != 0x1111 {
					t.Errorf("simhash = %v, want the first sample's kept for comparison by distance", got.Page.SimHash)
				}
			},
		},
		{
			"form field",
			func(o *model.ServiceObservation) { o.Page.Forms[0].Fields[0].Name = "query" },
			[]string{"forms"},
			func(t *testing.T, got model.ServiceObservation) {
				if got.Page.Forms != nil {
					t.Errorf("forms = %+v", got.Page.Forms)
				}
			},
		},
		{
			"script",
			func(o *model.ServiceObservation) {
				o.Page.Scripts = []string{"https://www.example.test/b.js", "https://ads.example.net/rotating-1.js"}
			},
			[]string{"scripts"},
			func(t *testing.T, got model.ServiceObservation) {
				if want := []string{"https://www.example.test/b.js"}; !slices.Equal(got.Page.Scripts, want) {
					t.Errorf("scripts = %q, want %q", got.Page.Scripts, want)
				}
			},
		},
		{
			"content type and generator",
			func(o *model.ServiceObservation) { o.Page.ContentType, o.Page.Generator = "application/xhtml+xml", "" },
			[]string{"content-type", "generator"},
			nil,
		},
		{
			"body only in one sample",
			func(o *model.ServiceObservation) { o.Page = nil },
			[]string{"page"},
			func(t *testing.T, got model.ServiceObservation) {
				if got.Page != nil {
					t.Errorf("page = %+v", got.Page)
				}
			},
		},
	}

	for _, tc := range cases {
		for _, order := range []string{"second sample differs", "first sample differs"} {
			a, b := sampleObservation(), sampleObservation()
			tc.change(&b)
			if order == "first sample differs" {
				a, b = b, a
			}
			got := merge(a, b)

			if !slices.Equal(got.Volatile, tc.volatile) {
				t.Errorf("%s (%s): volatile = %v, want %v", tc.name, order, got.Volatile, tc.volatile)
			}
			// The checks describe the result from the unchanged sample's
			// point of view.
			if tc.check != nil && order == "second sample differs" {
				tc.check(t, got)
			}
		}
	}
}

func TestMergeAccumulatesAcrossSamples(t *testing.T) {
	a, b, c := sampleObservation(), sampleObservation(), sampleObservation()
	b.Page.Title = "Other"
	c.Headers.Values["server"] = "Apache"

	got := merge(merge(a, b), c)
	if want := []string{"title", "value:server"}; !slices.Equal(got.Volatile, want) {
		t.Errorf("volatile = %v, want %v", got.Volatile, want)
	}
	if got.Page.Title != "" {
		t.Errorf("title = %q, want it to stay masked", got.Page.Title)
	}
}

func TestMergeWithoutBodies(t *testing.T) {
	a, b := sampleObservation(), sampleObservation()
	a.Page, b.Page = nil, nil

	got := merge(a, b)
	if got.Page != nil || len(got.Volatile) != 0 {
		t.Errorf("page = %+v, volatile = %v", got.Page, got.Volatile)
	}
}
