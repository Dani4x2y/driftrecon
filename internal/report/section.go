package report

import (
	"io"
	"strings"
	"unicode/utf8"
)

// Section is a titled block of labelled values, the detail view of one
// record.
type Section struct {
	Title string
	rows  []sectionRow
}

type sectionRow struct {
	label string
	lines []string
}

// Add appends a row. A value may span several lines; empty ones are dropped,
// and a row that is left without any is not added.
func (s *Section) Add(label string, lines ...string) {
	var kept []string
	for _, line := range lines {
		if line != "" {
			kept = append(kept, line)
		}
	}
	if len(kept) > 0 {
		s.rows = append(s.rows, sectionRow{label: label, lines: kept})
	}
}

// Render writes the title followed by the rows, with the values aligned in
// one column and continuation lines under the first.
func (s *Section) Render(w io.Writer) error {
	width := 0
	for _, row := range s.rows {
		width = max(width, utf8.RuneCountInString(row.label))
	}

	var b strings.Builder
	b.WriteString(s.Title)
	b.WriteByte('\n')
	for _, row := range s.rows {
		for i, line := range row.lines {
			label := ""
			if i == 0 {
				label = row.label
			}
			b.WriteString("  ")
			b.WriteString(label)
			b.WriteString(strings.Repeat(" ", width-utf8.RuneCountInString(label)+columnGap))
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
