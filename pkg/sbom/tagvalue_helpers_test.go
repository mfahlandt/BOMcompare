package sbom

import "testing"

func TestParseTagChecksum(t *testing.T) {
	if cs, ok := parseTagChecksum("SHA256: abc123"); !ok || cs.Algorithm != "SHA256" || cs.ChecksumValue != "abc123" {
		t.Errorf("colon form = %+v ok=%v", cs, ok)
	}
	if cs, ok := parseTagChecksum("SHA256 abc123"); !ok || cs.Algorithm != "SHA256" || cs.ChecksumValue != "abc123" {
		t.Errorf("space form = %+v ok=%v", cs, ok)
	}
	if _, ok := parseTagChecksum("garbage"); ok {
		t.Error("malformed checksum should not parse")
	}
}

func TestParseTagExternalRef(t *testing.T) {
	ref, ok := parseTagExternalRef("PACKAGE-MANAGER purl pkg:golang/x@v1.0.0")
	if !ok || ref.ReferenceType != "purl" || ref.ReferenceLocator != "pkg:golang/x@v1.0.0" {
		t.Errorf("ext ref = %+v ok=%v", ref, ok)
	}
	if _, ok := parseTagExternalRef("only two"); ok {
		t.Error("two-field external ref should not parse")
	}
}

func TestParseTagRelationship(t *testing.T) {
	rel, ok := parseTagRelationship("SPDXRef-A DEPENDS_ON SPDXRef-B")
	if !ok || rel.SPDXElementID != "SPDXRef-A" || rel.RelationshipType != "DEPENDS_ON" || rel.RelatedSPDXElement != "SPDXRef-B" {
		t.Errorf("relationship = %+v ok=%v", rel, ok)
	}
	if _, ok := parseTagRelationship("A DEPENDS_ON"); ok {
		t.Error("arity-2 relationship should not parse")
	}
}

func TestSplitToolVersion(t *testing.T) {
	cases := []struct {
		in, wantName, wantVer string
	}{
		{"syft 1.42.3", "syft", "1.42.3"},
		{"syft-1.42.3", "syft", "1.42.3"},
		{"mikebom-0.1.0-alpha.47", "mikebom", "0.1.0-alpha.47"},
		{"tool-no-version", "tool-no-version", ""},
		{"Source Auditor Open Source Console", "Source Auditor Open Source Console", ""},
		{"Microsoft SBOM Tool v2.2.0", "Microsoft SBOM Tool", "v2.2.0"},
	}
	for _, c := range cases {
		n, v := splitToolVersion(c.in)
		if n != c.wantName || v != c.wantVer {
			t.Errorf("splitToolVersion(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.wantName, c.wantVer)
		}
	}
}

func TestToolLabelStripsSourceProvenance(t *testing.T) {
	label, name := toolLabel([]string{"Organization: Acme", "Tool: syft-1.42.3 source: filesystem"})
	if name != "syft" {
		t.Errorf("name = %q, want syft", name)
	}
	if label != "syft v1.42.3" {
		t.Errorf("label = %q, want 'syft v1.42.3'", label)
	}
}

func TestToolLabelFallback(t *testing.T) {
	if label, name := toolLabel(nil); label != "unknown-tool" || name != "unknown" {
		t.Errorf("empty creators = (%q,%q), want (unknown-tool, unknown)", label, name)
	}
}

func TestIsStdlib(t *testing.T) {
	cases := []struct {
		name, purl string
		want       bool
	}{
		{"stdlib", "", true},
		{"go-stdlib", "", true},
		{"foo", "pkg:golang/std", true},
		{"foo", "pkg:golang/github.com/x/y", false},
		{"cobra", "", false},
	}
	for _, c := range cases {
		if got := isStdlib(c.name, c.purl); got != c.want {
			t.Errorf("isStdlib(%q,%q) = %v, want %v", c.name, c.purl, got, c.want)
		}
	}
}

func TestFirstNonSpaceSkipsBOM(t *testing.T) {
	if b := firstNonSpace([]byte("\ufeff  {")); b != '{' {
		t.Errorf("firstNonSpace skipping BOM = %q, want '{'", b)
	}
	if b := firstNonSpace([]byte("   ")); b != 0 {
		t.Errorf("firstNonSpace(blank) = %q, want 0", b)
	}
}
