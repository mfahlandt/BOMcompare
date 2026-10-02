package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func pkgByName(p *Parsed) map[string]*NormalizedPackage {
	m := map[string]*NormalizedPackage{}
	for i := range p.Packages {
		m[p.Packages[i].Name] = &p.Packages[i]
	}
	return m
}

func TestLoadSPDX3Fixture(t *testing.T) {
	p, err := Load("../../testdata/source.spdx3.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Format != FormatSPDX3JSONLD {
		t.Errorf("format = %q, want %q", p.Format, FormatSPDX3JSONLD)
	}
	if p.ToolLabel != "mikebom v0.1.0-alpha.47" {
		t.Errorf("tool label = %q", p.ToolLabel)
	}
	if p.Context != "source" {
		t.Errorf("context = %q, want source (from software_sbomType)", p.Context)
	}
	if p.Meta.SpecVersion != "SPDX-3.0.1" || p.Meta.Created == "" || p.Meta.Lifecycle != "source" {
		t.Errorf("meta = %+v", p.Meta)
	}
	if len(p.Meta.Authors) != 1 || p.Meta.Authors[0] != "mikebom contributors" {
		t.Errorf("authors = %v", p.Meta.Authors)
	}
	if len(p.Packages) != 4 {
		t.Fatalf("packages = %d, want 4", len(p.Packages))
	}

	by := pkgByName(p)
	main := by["demo"]
	if main == nil || !main.IsMainModule {
		t.Fatal("demo should be the main module (rootElement via software_Sbom)")
	}
	if main.Supplier != "Organization: example" {
		t.Errorf("inline suppliedBy not resolved: %q", main.Supplier)
	}
	if main.LicenseDeclared != "Apache-2.0" || main.LicenseConcluded != NoAssertion {
		t.Errorf("main licenses = %q / %q", main.LicenseDeclared, main.LicenseConcluded)
	}
	if main.PURLType != "generic" || len(main.CPEs) != 1 {
		t.Errorf("main identity = %q %v", main.PURL, main.CPEs)
	}

	cobra := by["github.com/spf13/cobra"]
	if cobra.PURL != "pkg:golang/github.com/spf13/cobra@v1.8.0" {
		t.Errorf("purl from externalIdentifier = %q", cobra.PURL)
	}
	if !cobra.HasSHA256 || cobra.Supplier != "Organization: github.com/spf13" {
		t.Errorf("cobra hash/supplier = %v / %q", cobra.HasSHA256, cobra.Supplier)
	}
	if cobra.IsMainModule {
		t.Error("cobra must not be flagged as main module")
	}

	if got := by["gopkg.in/yaml.v3"].LicenseDeclared; got != "MIT AND Apache-2.0" {
		t.Errorf("ConjunctiveLicenseSet = %q", got)
	}
	if !by["github.com/stretchr/testify"].IsTestScoped {
		t.Error("testify should be test-scoped via LifecycleScopedRelationship scope=test")
	}

	var testEdge, describes bool
	for _, r := range p.Relationships {
		switch r.RelationshipType {
		case "TEST_DEPENDENCY_OF":
			testEdge = r.SPDXElementID == "https://example.com/demo/source#pkg-testify"
		case "DESCRIBES":
			describes = true
		}
		if r.RelationshipType == "HAS_DECLARED_LICENSE" {
			t.Error("license relationships must not be kept as graph edges")
		}
	}
	if !testEdge || !describes {
		t.Errorf("relationships not converted: %+v", p.Relationships)
	}
	if len(p.DocAnnotations) != 2 || len(main.Annotations) != 1 {
		t.Errorf("annotations: doc=%d main=%d", len(p.DocAnnotations), len(main.Annotations))
	}
}

func TestSPDX3LicenseExpressions(t *testing.T) {
	doc := `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[
	 {"spdxId":"urn:p","type":"software_Package","name":"p","software_packageVersion":"1"},
	 {"spdxId":"urn:with","type":"expandedlicensing_WithAdditionOperator",
	  "expandedlicensing_subjectExtendableLicense":"http://spdx.org/licenses/GPL-2.0-or-later",
	  "expandedlicensing_subjectAddition":"http://spdx.org/licenses/Classpath-exception-2.0"},
	 {"spdxId":"urn:or","type":"expandedlicensing_DisjunctiveLicenseSet",
	  "expandedlicensing_member":["http://spdx.org/licenses/MIT","urn:with",
	   {"spdxId":"urn:later","type":"expandedlicensing_OrLaterOperator","expandedlicensing_subjectLicense":"http://spdx.org/licenses/EPL-1.0"}]},
	 {"spdxId":"urn:r1","type":"Relationship","relationshipType":"hasConcludedLicense","from":"urn:p","to":["urn:or"]},
	 {"spdxId":"urn:r2","type":"Relationship","relationshipType":"hasDeclaredLicense","from":"urn:p",
	  "to":["https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoneLicense"]}
	]}`
	p := loadString(t, doc)
	pk := p.Packages[0]
	want := "MIT OR (GPL-2.0-or-later WITH Classpath-exception-2.0) OR EPL-1.0+"
	if pk.LicenseConcluded != want {
		t.Errorf("concluded = %q, want %q", pk.LicenseConcluded, want)
	}
	if pk.LicenseDeclared != None {
		t.Errorf("declared = %q, want NONE", pk.LicenseDeclared)
	}
}

func TestSPDX3ScopesAndRelationshipNames(t *testing.T) {
	doc := `{"@graph":[
	 {"spdxId":"urn:doc","type":"SpdxDocument","rootElement":["urn:a"]},
	 {"spdxId":"urn:a","type":"software_Package","name":"a"},
	 {"spdxId":"urn:b","type":"software_Package","name":"b"},
	 {"spdxId":"urn:c","type":"software_Package","name":"c"},
	 {"spdxId":"urn:r1","type":"LifecycleScopedRelationship","relationshipType":"dependsOn","scope":"build","from":"urn:a","to":["urn:b"]},
	 {"spdxId":"urn:r2","type":"Relationship","relationshipType":"hasStaticLink","from":"urn:a","to":["urn:c"]},
	 {"spdxId":"urn:v","type":"security_VexAffectedVulnAssessmentRelationship","relationshipType":"affects","from":"urn:x","to":["urn:a"]}
	]}`
	p := loadString(t, doc)
	got := map[string]bool{}
	for _, r := range p.Relationships {
		got[r.RelationshipType+":"+r.SPDXElementID+">"+r.RelatedSPDXElement] = true
	}
	for _, want := range []string{"BUILD_DEPENDENCY_OF:urn:b>urn:a", "HAS_STATIC_LINK:urn:a>urn:c"} {
		if !got[want] {
			t.Errorf("missing relationship %s in %v", want, got)
		}
	}
	if len(p.Relationships) != 2 {
		t.Errorf("security assessment relationships should be skipped: %v", got)
	}
	if !pkgByName(p)["a"].IsMainModule {
		t.Error("rootElement of SpdxDocument should be the main module")
	}
}

func TestCamelToUpperSnake(t *testing.T) {
	for in, want := range map[string]string{
		"dependsOn":             "DEPENDS_ON",
		"hasOptionalDependency": "HAS_OPTIONAL_DEPENDENCY",
		"describes":             "DESCRIBES",
	} {
		if got := camelToUpperSnake(in); got != want {
			t.Errorf("camelToUpperSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSPDX3RejectsEmptyGraph(t *testing.T) {
	if _, err := parseSPDX3([]byte(`{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`)); err == nil {
		t.Error("expected error for empty graph")
	}
}

func loadString(t *testing.T, content string) *Parsed {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}
