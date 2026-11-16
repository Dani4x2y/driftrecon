package report

import (
	"strings"
	"testing"
)

func TestSectionRender(t *testing.T) {
	s := Section{Title: "service https://www.example.com"}
	s.Add("state", "live")
	s.Add("response", "302 > /login", "200")
	s.Add("title", "")
	s.Add("trust issues", "", "self_signed", "")
	s.Add("volatile")

	var b strings.Builder
	if err := s.Render(&b); err != nil {
		t.Fatal(err)
	}
	want := "" +
		"service https://www.example.com\n" +
		"  state         live\n" +
		"  response      302 > /login\n" +
		"                200\n" +
		"  trust issues  self_signed\n"
	if b.String() != want {
		t.Errorf("rendered:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestSectionAlignsWideLabels(t *testing.T) {
	s := Section{Title: "host żółw.example"}
	s.Add("źródła", "crtsh")
	s.Add("stan", "live")

	var b strings.Builder
	if err := s.Render(&b); err != nil {
		t.Fatal(err)
	}
	want := "host żółw.example\n  źródła  crtsh\n  stan    live\n"
	if b.String() != want {
		t.Errorf("rendered:\n%q\nwant:\n%q", b.String(), want)
	}
}

func TestSectionWithoutRows(t *testing.T) {
	s := Section{Title: "host a.example"}
	s.Add("sources", "")

	var b strings.Builder
	if err := s.Render(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != "host a.example\n" {
		t.Errorf("rendered %q, want the title alone", b.String())
	}
}

func TestSectionReportsWriteErrors(t *testing.T) {
	s := Section{Title: "host a.example"}
	if err := s.Render(failingWriter{}); err == nil {
		t.Error("a failed write was not reported")
	}
}
