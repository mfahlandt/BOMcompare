// Command sbom-comparison compares two SPDX 2.3 JSON SBOMs and produces a
// structured quality diff report (markdown, JSON or summary).
//
// Exit codes:
//
//	0  success, no significant differences (or --exit-on-diff not set)
//	1  error (bad args, unreadable/invalid SBOM)
//	2  significant differences found AND --exit-on-diff set
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/seebom-labs/BOMHort/BOMcompare/pkg/compare"
	"github.com/seebom-labs/BOMHort/BOMcompare/pkg/report"
	"github.com/seebom-labs/BOMHort/BOMcompare/pkg/sbom"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbom-comparison", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		fileA      = fs.String("a", "", "path to first SBOM (SPDX or CycloneDX; or first positional arg)")
		fileB      = fs.String("b", "", "path to second SBOM (SPDX or CycloneDX; or second positional arg)")
		format     = fs.String("format", "markdown", "output format: markdown | json | summary")
		out        = fs.String("o", "", "write report to this file instead of stdout")
		exitOnDiff = fs.Bool("exit-on-diff", false, "exit with code 2 if significant differences are found (CI gating)")
		threshold  = fs.Int("diff-threshold", 1, "minimum number of runtime-unique packages that counts as a significant diff")
		showVer    = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "sbom-comparison %s — compare two SBOMs (SPDX or CycloneDX)\n\n", version)
		fmt.Fprintf(stderr, "Usage:\n  sbom-comparison [flags] <sbom-a> <sbom-b>\n\n")
		fmt.Fprintf(stderr, "Supported formats (auto-detected): SPDX JSON, SPDX tag-value,\n")
		fmt.Fprintf(stderr, "CycloneDX JSON, CycloneDX XML. The two inputs may be in different formats.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExamples:\n")
		fmt.Fprintf(stderr, "  sbom-comparison a.spdx.json b.spdx.json\n")
		fmt.Fprintf(stderr, "  sbom-comparison mikebom.spdx.json syft.cdx.json   # cross-format\n")
		fmt.Fprintf(stderr, "  sbom-comparison --format summary a.spdx b.cdx.xml\n")
		fmt.Fprintf(stderr, "  sbom-comparison --format json -o report.json a.spdx.json b.cdx.json\n")
		fmt.Fprintf(stderr, "  sbom-comparison --exit-on-diff old.spdx.json new.spdx.json   # CI gate\n")
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showVer {
		fmt.Fprintf(stdout, "sbom-comparison %s\n", version)
		return 0
	}

	// Resolve inputs: flags take precedence, else positional args.
	pathA, pathB := *fileA, *fileB
	pos := fs.Args()
	if pathA == "" && len(pos) > 0 {
		pathA = pos[0]
	}
	if pathB == "" && len(pos) > 1 {
		pathB = pos[1]
	}
	if pathA == "" || pathB == "" {
		fmt.Fprintln(stderr, "error: two SBOM files are required")
		fs.Usage()
		return 1
	}

	f, err := parseFormat(*format)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	a, err := sbom.Load(pathA)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	b, err := sbom.Load(pathB)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	opts := compare.DefaultOptions()
	if *threshold >= 0 {
		opts.SignificantThreshold = *threshold
	}
	rep := compare.Run(a, b, opts)

	rendered, err := report.Render(rep, f)
	if err != nil {
		fmt.Fprintf(stderr, "error: rendering report: %v\n", err)
		return 1
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(stderr, "error: writing %s: %v\n", *out, err)
			return 1
		}
		fmt.Fprintf(stderr, "report written to %s\n", *out)
	} else {
		fmt.Fprintln(stdout, rendered)
	}

	if *exitOnDiff && rep.Overall.Significant {
		return 2
	}
	return 0
}

func parseFormat(s string) (report.Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "markdown", "md":
		return report.FormatMarkdown, nil
	case "json":
		return report.FormatJSON, nil
	case "summary", "table":
		return report.FormatSummary, nil
	default:
		return "", fmt.Errorf("unknown format %q (use markdown, json or summary)", s)
	}
}
