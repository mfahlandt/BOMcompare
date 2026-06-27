package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/seebom-labs/BOMHort/BOMcompare/pkg/report"
)

func TestParseFormat(t *testing.T) {
	cases := []struct {
		in   string
		want report.Format
		err  bool
	}{
		{"", report.FormatMarkdown, false},
		{"markdown", report.FormatMarkdown, false},
		{"MD", report.FormatMarkdown, false},
		{"json", report.FormatJSON, false},
		{" Summary ", report.FormatSummary, false},
		{"table", report.FormatSummary, false},
		{"xml", "", true},
	}
	for _, c := range cases {
		got, err := parseFormat(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseFormat(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFormat(%q) unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parseFormat(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("--version exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "sbom-comparison") {
		t.Errorf("--version stdout = %q, want a version line", out.String())
	}
}

func TestRunMissingArgs(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 1 {
		t.Fatalf("no args exit = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "two SBOM files are required") {
		t.Errorf("expected a usage error, got %q", errb.String())
	}
}

func TestRunBadFormat(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--format", "xml", "testdata/a", "testdata/b"}, &out, &errb)
	if code != 1 {
		t.Fatalf("bad format exit = %d, want 1", code)
	}
}

func TestRunHappyPath(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{
		"--format", "summary",
		"testdata/../testdata/source.spdx.json", // path normalization still resolves
		"testdata/../testdata/binary.spdx.json",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("happy path exit = %d, want 0 (stderr=%q)", code, errb.String())
	}
	if !strings.Contains(out.String(), "OVERALL (weighted)") {
		t.Errorf("summary output missing scorecard: %q", out.String())
	}
}

func TestRunExitOnDiff(t *testing.T) {
	var out, errb bytes.Buffer
	// A version mismatch is always significant → exit code 2 when gating.
	code := run([]string{
		"--exit-on-diff",
		"testdata/source-version-mismatch.spdx.json",
		"testdata/binary.spdx.json",
	}, &out, &errb)
	if code != 2 {
		t.Fatalf("--exit-on-diff with a version mismatch exit = %d, want 2", code)
	}
}
