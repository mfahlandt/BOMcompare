package sbom

import "testing"

// TestDetectFormat verifies the format sniffer across all four serializations
// using both the on-disk fixtures and small literal snippets.
func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"spdx-json", `{"spdxVersion":"SPDX-2.3","packages":[]}`, FormatSPDXJSON},
		{"cyclonedx-json-bomformat", `{"bomFormat":"CycloneDX","specVersion":"1.5"}`, FormatCycloneDXJSON},
		{"cyclonedx-json-specversion-only", `{"specVersion":"1.4","components":[]}`, FormatCycloneDXJSON},
		{"cyclonedx-xml", `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`, FormatCycloneDXXML},
		{"cyclonedx-xml-no-prolog", `<bom version="1"></bom>`, FormatCycloneDXXML},
		{"spdx-tagvalue", "SPDXVersion: SPDX-2.3\nPackageName: foo\n", FormatSPDXTagValue},
		{"tagvalue-leading-comment", "# header\nSPDXVersion: SPDX-2.3\n", FormatSPDXTagValue},
		{"unknown", "just some random text without markers", FormatUnknown},
		{"empty", "", FormatUnknown},
		{"json-with-bom-prefix", "\ufeff{\"spdxVersion\":\"SPDX-2.3\"}", FormatSPDXJSON},
		{"spdx3-context", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[{"type":"CreationInfo","specVersion":"3.0.1"}]}`, FormatSPDX3JSONLD},
		{"spdx3-graph-no-context", `{"@graph":[{"type":"software_Package","spdxId":"urn:x"}]}`, FormatSPDX3JSONLD},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectFormat([]byte(c.data)); got != c.want {
				t.Errorf("DetectFormat(%s) = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

// TestLoadAllFormats ensures every fixture format loads and produces a sane
// normalized view with a labeled tool and a main module.
func TestLoadAllFormats(t *testing.T) {
	cases := []struct {
		path       string
		wantFormat string
		wantTool   string // substring expected in ToolLabel
	}{
		{"../../testdata/binary.spdx.json", FormatSPDXJSON, "syft"},
		{"../../testdata/binary.spdx", FormatSPDXTagValue, "syft"},
		{"../../testdata/binary.cdx.json", FormatCycloneDXJSON, "cyclonedx-gomod"},
		{"../../testdata/binary.cdx.xml", FormatCycloneDXXML, "cyclonedx-gomod"},
	}
	for _, c := range cases {
		t.Run(c.wantFormat, func(t *testing.T) {
			p, err := Load(c.path)
			if err != nil {
				t.Fatalf("Load(%s): %v", c.path, err)
			}
			if p.Format != c.wantFormat {
				t.Errorf("Format = %q, want %q", p.Format, c.wantFormat)
			}
			if len(p.Packages) == 0 {
				t.Fatal("no packages parsed")
			}
			if !containsSub(p.ToolLabel, c.wantTool) {
				t.Errorf("ToolLabel = %q, want substring %q", p.ToolLabel, c.wantTool)
			}
			var sawMain bool
			for i := range p.Packages {
				if p.Packages[i].IsMainModule {
					sawMain = true
				}
			}
			if !sawMain {
				t.Error("expected a main module to be flagged")
			}
		})
	}
}

// TestCycloneDXNormalization checks the CycloneDX-specific field mappings:
// purl/cpe/hash/license/supplier/scope and dependency-graph conversion.
func TestCycloneDXNormalization(t *testing.T) {
	p, err := Load("../../testdata/binary.cdx.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	byName := map[string]*NormalizedPackage{}
	for i := range p.Packages {
		byName[p.Packages[i].Name] = &p.Packages[i]
	}

	cobra := byName["github.com/spf13/cobra"]
	if cobra == nil {
		t.Fatal("cobra component not normalized (group+name join failed?)")
	}
	if cobra.PURL != "pkg:golang/github.com/spf13/cobra@v1.8.0" {
		t.Errorf("cobra purl = %q", cobra.PURL)
	}
	if cobra.LicenseConcluded != "Apache-2.0" {
		t.Errorf("cobra licenseConcluded = %q, want Apache-2.0", cobra.LicenseConcluded)
	}
	if !cobra.HasSHA256 {
		t.Error("cobra should have SHA256 (alg SHA-256 must normalize)")
	}
	if len(cobra.CPEs) != 1 {
		t.Errorf("cobra CPEs = %v, want one", cobra.CPEs)
	}
	if cobra.Supplier != "github.com/spf13" {
		t.Errorf("cobra supplier = %q", cobra.Supplier)
	}
	if cobra.IsTestScoped {
		t.Error("cobra is scope=required, should not be test-scoped")
	}

	// testify is scope=optional -> treated as test-scoped.
	testify := byName["github.com/stretchr/testify"]
	if testify == nil {
		t.Fatal("testify component missing")
	}
	if !testify.IsTestScoped {
		t.Error("testify (scope=optional) should be test-scoped")
	}

	// Dependency graph: demo DEPENDS_ON cobra + testify, plus a DESCRIBES anchor.
	var describes, dependsOn int
	for _, r := range p.Relationships {
		switch r.RelationshipType {
		case "DESCRIBES":
			describes++
		case "DEPENDS_ON":
			dependsOn++
		}
	}
	if describes != 1 {
		t.Errorf("DESCRIBES count = %d, want 1", describes)
	}
	if dependsOn != 2 {
		t.Errorf("DEPENDS_ON count = %d, want 2", dependsOn)
	}
}

// TestCycloneDXXMLEquivalence verifies the XML parser yields the same key facts
// as the JSON one for the shared cobra component.
func TestCycloneDXXMLEquivalence(t *testing.T) {
	x, err := Load("../../testdata/binary.cdx.xml")
	if err != nil {
		t.Fatalf("load xml: %v", err)
	}
	var cobra *NormalizedPackage
	for i := range x.Packages {
		if x.Packages[i].Name == "github.com/spf13/cobra" {
			cobra = &x.Packages[i]
		}
	}
	if cobra == nil {
		t.Fatal("cobra not parsed from XML")
	}
	if cobra.PURL != "pkg:golang/github.com/spf13/cobra@v1.8.0" {
		t.Errorf("xml cobra purl = %q", cobra.PURL)
	}
	if cobra.LicenseConcluded != "Apache-2.0" {
		t.Errorf("xml cobra license = %q", cobra.LicenseConcluded)
	}
	if !cobra.HasSHA256 {
		t.Error("xml cobra should have SHA256")
	}
	if len(cobra.CPEs) != 1 {
		t.Errorf("xml cobra CPEs = %v, want one", cobra.CPEs)
	}
}

// TestSPDXTagValueParsing checks the tag-value parser including a multi-line
// <text> block and external-ref/checksum parsing.
func TestSPDXTagValueParsing(t *testing.T) {
	p, err := Load("../../testdata/binary.spdx")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(p.Packages) != 3 {
		t.Fatalf("packages = %d, want 3", len(p.Packages))
	}

	byName := map[string]*NormalizedPackage{}
	for i := range p.Packages {
		byName[p.Packages[i].Name] = &p.Packages[i]
	}

	cobra := byName["github.com/spf13/cobra"]
	if cobra == nil {
		t.Fatal("cobra missing")
	}
	if cobra.Version != "v1.8.0" {
		t.Errorf("cobra version = %q", cobra.Version)
	}
	if cobra.LicenseConcluded != "Apache-2.0" {
		t.Errorf("cobra licenseConcluded = %q", cobra.LicenseConcluded)
	}
	if !cobra.HasSHA256 {
		t.Error("cobra should have SHA256 from PackageChecksum line")
	}
	if cobra.PURL != "pkg:golang/github.com/spf13/cobra@v1.8.0" {
		t.Errorf("cobra purl = %q", cobra.PURL)
	}
	if len(cobra.CPEs) != 1 {
		t.Errorf("cobra CPEs = %v, want one", cobra.CPEs)
	}

	if std := byName["stdlib"]; std == nil || !std.IsStdlib {
		t.Error("stdlib should be parsed and flagged")
	}

	// DESCRIBES + main module.
	var sawMain bool
	for i := range p.Packages {
		if p.Packages[i].IsMainModule {
			sawMain = true
		}
	}
	if !sawMain {
		t.Error("main module not flagged from tag-value DESCRIBES")
	}
}

func containsSub(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
