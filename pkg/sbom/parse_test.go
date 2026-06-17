package sbom

import "testing"

func TestPURLParsing(t *testing.T) {
	cases := []struct {
		purl       string
		name       string
		wantType   string
		wantModule string
		wantVer    string
		wantQual   bool
	}{
		{"pkg:golang/github.com/spf13/cobra@v1.8.0", "github.com/spf13/cobra", "golang", "github.com/spf13/cobra", "v1.8.0", false},
		{"pkg:generic/demo@1.0.0", "demo", "generic", "demo", "1.0.0", false},
		{"pkg:npm/left-pad@1.3.0?arch=any", "left-pad", "npm", "left-pad", "1.3.0", true},
		{"", "fallback-name", "", "fallback-name", "", false},
	}
	for _, c := range cases {
		gotType, gotModule := parsePURL(c.purl, c.name)
		if gotType != c.wantType {
			t.Errorf("parsePURL(%q) type = %q, want %q", c.purl, gotType, c.wantType)
		}
		if gotModule != c.wantModule {
			t.Errorf("parsePURL(%q) module = %q, want %q", c.purl, gotModule, c.wantModule)
		}
		if v := PURLVersion(c.purl); v != c.wantVer {
			t.Errorf("PURLVersion(%q) = %q, want %q", c.purl, v, c.wantVer)
		}
		if q := PURLHasQualifiers(c.purl); q != c.wantQual {
			t.Errorf("PURLHasQualifiers(%q) = %v, want %v", c.purl, q, c.wantQual)
		}
	}
}

func TestNormalizeFlagsMainAndStdlib(t *testing.T) {
	bin, err := Load("../../testdata/binary.spdx.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var sawMain, sawStdlib bool
	for i := range bin.Packages {
		p := &bin.Packages[i]
		if p.IsMainModule {
			sawMain = true
		}
		if p.IsStdlib {
			sawStdlib = true
			if p.HasSHA256 {
				t.Error("stdlib fixture unexpectedly has SHA256")
			}
		}
	}
	if !sawMain {
		t.Error("expected a main module to be flagged in the binary SBOM")
	}
	if !sawStdlib {
		t.Error("expected stdlib to be flagged in the binary SBOM")
	}
}
