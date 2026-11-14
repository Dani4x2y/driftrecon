// Package report renders scan data for people.
package report

import (
	"io"
	"strings"
	"unicode/utf8"
)

const columnGap = 2

// Table is a plain-text table with a header row.
type Table struct {
	Header []string
	Rows   [][]string
}

// Render writes the table with every column padded to its widest cell. Rows
// shorter than the header are filled with empty cells; extra cells are
// dropped.
func (t Table) Render(w io.Writer) error {
	widths := make([]int, len(t.Header))
	for i, cell := range t.Header {
		widths[i] = utf8.RuneCountInString(cell)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) {
				widths[i] = max(widths[i], utf8.RuneCountInString(cell))
			}
		}
	}

	var b strings.Builder
	writeRow := func(row []string) {
		var line strings.Builder
		for i, width := range widths {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			line.WriteString(cell)
			line.WriteString(strings.Repeat(" ", width-utf8.RuneCountInString(cell)+columnGap))
		}
		b.WriteString(strings.TrimRight(line.String(), " "))
		b.WriteByte('\n')
	}

	writeRow(t.Header)
	for _, row := range t.Rows {
		writeRow(row)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
