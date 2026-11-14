package report

import (
	"errors"
	"strings"
	"testing"
)

func render(t *testing.T, table Table) string {
	t.Helper()
	var b strings.Builder
	if err := table.Render(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestTableAlignsColumns(t *testing.T) {
	got := render(t, Table{
		Header: []string{"HOST", "STATE", "ADDRESSES"},
		Rows: [][]string{
			{"example.com", "live", "192.0.2.1"},
			{"staging-api.example.com", "unresolved", ""},
			{"a.example.com", "live", "192.0.2.10, 192.0.2.11"},
		},
	})
	want := "" +
		"HOST                     STATE       ADDRESSES\n" +
		"example.com              live        192.0.2.1\n" +
		"staging-api.example.com  unresolved\n" +
		"a.example.com            live        192.0.2.10, 192.0.2.11\n"
	if got != want {
		t.Errorf("table:\n%s\nwant:\n%s", got, want)
	}
}

func TestTableMeasuresRunesNotBytes(t *testing.T) {
	got := render(t, Table{
		Header: []string{"NAME", "NOTE"},
		Rows: [][]string{
			{"żółć", "x"},
			{"abcdef", "y"},
		},
	})
	want := "" +
		"NAME    NOTE\n" +
		"żółć    x\n" +
		"abcdef  y\n"
	if got != want {
		t.Errorf("table:\n%s\nwant:\n%s", got, want)
	}
}

func TestTableToleratesRaggedRows(t *testing.T) {
	got := render(t, Table{
		Header: []string{"A", "B"},
		Rows: [][]string{
			{"1"},
			{"1", "2", "dropped"},
			{},
		},
	})
	want := "A  B\n1\n1  2\n\n"
	if got != want {
		t.Errorf("table = %q, want %q", got, want)
	}
}

func TestTableWithoutRows(t *testing.T) {
	if got, want := render(t, Table{Header: []string{"HOST", "STATE"}}), "HOST  STATE\n"; got != want {
		t.Errorf("table = %q, want %q", got, want)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

func TestTableReportsWriteErrors(t *testing.T) {
	err := Table{Header: []string{"A"}}.Render(failingWriter{})
	if err == nil {
		t.Fatal("write error was swallowed")
	}
}
