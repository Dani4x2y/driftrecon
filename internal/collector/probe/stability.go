package probe

import (
	"slices"
	"strings"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// merge keeps what two observations of one service agree on. A feature that
// differs between two requests sent moments apart is noise as far as drift
// between scans goes, so it is dropped from the result and named in Volatile
// instead. That it is volatile is information in its own right: a Server
// header that changes from one request to the next means the backends behind
// a load balancer are not alike.
func merge(a, b model.ServiceObservation) model.ServiceObservation {
	out := model.ServiceObservation{URL: a.URL, Volatile: slices.Concat(a.Volatile, b.Volatile)}
	note := func(feature string) {
		out.Volatile = append(out.Volatile, feature)
	}

	if slices.Equal(a.Hops, b.Hops) {
		out.Hops = a.Hops
	} else {
		note("redirect")
	}
	out.Headers = mergeHeaders(a.Headers, b.Headers, note)
	out.Page = mergePage(a.Page, b.Page, note)

	slices.Sort(out.Volatile)
	out.Volatile = slices.Compact(out.Volatile)
	return out
}

func mergeHeaders(a, b *model.Headers, note func(string)) *model.Headers {
	if a == nil || b == nil {
		if a != b {
			note("headers")
		}
		return nil
	}
	out := &model.Headers{}

	// The names both samples have are compared in the order each sample
	// sent them. If that order differs, it is not a property of the service
	// and the names are kept as a set.
	var fromA, fromB []string
	for _, name := range a.Names {
		if slices.Contains(b.Names, name) {
			fromA = append(fromA, name)
		} else {
			note("header:" + strings.ToLower(name))
		}
	}
	for _, name := range b.Names {
		if slices.Contains(a.Names, name) {
			fromB = append(fromB, name)
		} else {
			note("header:" + strings.ToLower(name))
		}
	}
	if !slices.Equal(fromA, fromB) {
		note("header-order")
		slices.Sort(fromA)
	}
	out.Names = fromA

	for name, value := range a.Values {
		if other, ok := b.Values[name]; ok && other == value {
			if out.Values == nil {
				out.Values = make(map[string]string)
			}
			out.Values[name] = value
		} else {
			note("value:" + name)
		}
	}
	for name := range b.Values {
		if _, ok := a.Values[name]; !ok {
			note("value:" + name)
		}
	}

	flagsB := make(map[string][]string, len(b.Cookies))
	for _, c := range b.Cookies {
		flagsB[c.Name] = c.Flags
	}
	inA := make(map[string]bool, len(a.Cookies))
	for _, c := range a.Cookies {
		inA[c.Name] = true
		if flags, ok := flagsB[c.Name]; ok && slices.Equal(flags, c.Flags) {
			out.Cookies = append(out.Cookies, c)
		} else {
			note("cookie:" + c.Name)
		}
	}
	for _, c := range b.Cookies {
		if !inA[c.Name] {
			note("cookie:" + c.Name)
		}
	}
	return out
}

func mergePage(a, b *model.Page, note func(string)) *model.Page {
	if a == nil || b == nil {
		if a != b {
			note("page")
		}
		return nil
	}
	pick := func(x, y, feature string) string {
		if x != y {
			note(feature)
			return ""
		}
		return x
	}

	out := &model.Page{
		ContentType: pick(a.ContentType, b.ContentType, "content-type"),
		Title:       pick(a.Title, b.Title, "title"),
		Generator:   pick(a.Generator, b.Generator, "generator"),
		Skeleton:    pick(a.Skeleton, b.Skeleton, "dom"),
		BodySHA256:  pick(a.BodySHA256, b.BodySHA256, "body"),
		Truncated:   a.Truncated || b.Truncated,
		// The SimHash is the one feature kept although it may differ: it is
		// compared by distance, which is what tolerates a document that is
		// never quite the same twice.
		SimHash: a.SimHash,
	}
	if out.SimHash == nil {
		out.SimHash = b.SimHash
	}

	if slices.EqualFunc(a.Forms, b.Forms, equalForms) {
		out.Forms = a.Forms
	} else {
		note("forms")
	}

	for _, script := range a.Scripts {
		if slices.Contains(b.Scripts, script) {
			out.Scripts = append(out.Scripts, script)
		}
	}
	if len(out.Scripts) != len(a.Scripts) || len(out.Scripts) != len(b.Scripts) {
		note("scripts")
	}
	return out
}

func equalForms(a, b model.Form) bool {
	return a.Method == b.Method && a.Action == b.Action && slices.Equal(a.Fields, b.Fields)
}
