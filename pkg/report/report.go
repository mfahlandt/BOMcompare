// Package report renders a compare.Report into markdown, JSON or a compact
// summary table.
package report

import (
	"strings"

	"github.com/mfahlandt/sbom-comparison/pkg/compare"
)

// Format enumerates the supported output formats.
type Format string

const (
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
	FormatSummary  Format = "summary"
)

// stars renders an integer 1-5 as filled/empty star glyphs.
func stars(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 5 {
		n = 5
	}
	return strings.Repeat("⭐", n)
}

// winnerOf compares two star values for a per-row winner label.
func winnerOf(a, b int, labelA, labelB string) string {
	switch {
	case a > b:
		return labelA
	case b > a:
		return labelB
	default:
		return "—"
	}
}

// trunc truncates a string for table cells.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// Render dispatches to the requested format.
func Render(r *compare.Report, f Format) (string, error) {
	switch f {
	case FormatJSON:
		return RenderJSON(r)
	case FormatSummary:
		return RenderSummary(r), nil
	case FormatMarkdown, "":
		return RenderMarkdown(r), nil
	default:
		return RenderMarkdown(r), nil
	}
}
