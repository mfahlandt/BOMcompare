package sbom

import "testing"

func TestCycloneDX16LicenseAcknowledgementAndLifecycle(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1","version":2,
	 "metadata":{"timestamp":"2026-01-01T00:00:00Z","lifecycles":[{"phase":"pre-build"}],
	  "authors":[{"name":"Jane"}],"manufacturer":{"name":"ACME"},
	  "tools":{"components":[{"type":"application","name":"cdxgen","version":"11.0.0"}]},
	  "component":{"bom-ref":"app","type":"application","name":"app","version":"1.0"}},
	 "components":[
	  {"bom-ref":"a","type":"library","name":"a","version":"1","purl":"pkg:npm/a@1",
	   "manufacturer":{"name":"A Corp"},"omniborId":["gitoid:blob:sha1:abc"],
	   "licenses":[{"license":{"id":"MIT","acknowledgement":"declared"}},
	               {"license":{"id":"Apache-2.0","acknowledgement":"concluded"}}]},
	  {"bom-ref":"b","type":"library","name":"b","version":"1",
	   "licenses":[{"expression":"MIT OR Apache-2.0","acknowledgement":"declared"}]},
	  {"bom-ref":"c","type":"library","name":"c","version":"1",
	   "licenses":[{"license":{"id":"BSD-3-Clause"}}]}],
	 "dependencies":[{"ref":"app","dependsOn":["a"]},{"ref":"c"}]}`
	p := loadString(t, doc)
	by := pkgByName(p)

	if a := by["a"]; a.LicenseDeclared != "MIT" || a.LicenseConcluded != "Apache-2.0" {
		t.Errorf("a licenses = %q / %q", a.LicenseDeclared, a.LicenseConcluded)
	}
	if b := by["b"]; b.LicenseDeclared != "MIT OR Apache-2.0" || b.LicenseConcluded != NoAssertion {
		t.Errorf("b licenses = %q / %q", b.LicenseDeclared, b.LicenseConcluded)
	}
	if c := by["c"]; c.LicenseDeclared != NoAssertion || c.LicenseConcluded != "BSD-3-Clause" {
		t.Errorf("c (no acknowledgement) licenses = %q / %q", c.LicenseDeclared, c.LicenseConcluded)
	}
	if a := by["a"]; a.Originator != "A Corp" || len(a.OtherIDs) != 1 {
		t.Errorf("a originator/ids = %q / %v", a.Originator, a.OtherIDs)
	}
	if p.Context != "source" {
		t.Errorf("context = %q, want source (lifecycle pre-build)", p.Context)
	}
	m := p.Meta
	if m.SpecVersion != "CycloneDX-1.6" || m.Lifecycle != "pre-build" || m.Created == "" ||
		m.DocVersion != "urn:uuid:1#2" || len(m.ToolVersions) != 1 {
		t.Errorf("meta = %+v", m)
	}
	if len(m.Authors) != 2 {
		t.Errorf("authors = %v, want Jane + ACME", m.Authors)
	}
	if !m.DependencyDeclared["c"] {
		t.Error("empty dependency entry should count as declared")
	}
}

func TestCycloneDXXML16(t *testing.T) {
	doc := `<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata>
    <timestamp>2026-01-01T00:00:00Z</timestamp>
    <lifecycles><lifecycle><phase>post-build</phase></lifecycle></lifecycles>
    <authors><author><name>Jane</name></author></authors>
  </metadata>
  <components>
    <component type="library" bom-ref="a">
      <name>a</name><version>1</version>
      <manufacturer><name>A Corp</name></manufacturer>
      <licenses>
        <license acknowledgement="declared"><id>MIT</id></license>
        <expression acknowledgement="concluded">MIT OR Apache-2.0</expression>
      </licenses>
    </component>
  </components>
</bom>`
	p := loadString(t, doc)
	a := pkgByName(p)["a"]
	if a.LicenseDeclared != "MIT" || a.LicenseConcluded != "MIT OR Apache-2.0" {
		t.Errorf("licenses = %q / %q", a.LicenseDeclared, a.LicenseConcluded)
	}
	if a.Originator != "A Corp" {
		t.Errorf("originator = %q", a.Originator)
	}
	if p.Meta.SpecVersion != "CycloneDX-1.6" || p.Meta.Lifecycle != "post-build" {
		t.Errorf("meta = %+v", p.Meta)
	}
	if p.Context != "binary" {
		t.Errorf("context = %q, want binary (post-build)", p.Context)
	}
}

func TestParsePURLEdgeCases(t *testing.T) {
	cases := []struct {
		purl, wantType, wantPath, wantVer string
	}{
		{"pkg:npm/%40angular/core@16.0.0", "npm", "@angular/core", "16.0.0"},
		{"pkg:npm/@angular/core@16.0.0", "npm", "@angular/core", "16.0.0"},
		{"pkg:npm/@angular/core", "npm", "@angular/core", ""},
		{"pkg:maven/org.x/y@1.0?repository_url=https://u@host/repo", "maven", "org.x/y", "1.0"},
		{"pkg:Golang/github.com/A/B@v1.0.0#sub", "golang", "github.com/a/b", "v1.0.0"},
	}
	for _, c := range cases {
		typ, path := parsePURL(c.purl, "fallback")
		if typ != c.wantType || path != c.wantPath {
			t.Errorf("parsePURL(%q) = %q,%q want %q,%q", c.purl, typ, path, c.wantType, c.wantPath)
		}
		if v := PURLVersion(c.purl); v != c.wantVer {
			t.Errorf("PURLVersion(%q) = %q, want %q", c.purl, v, c.wantVer)
		}
	}
}

func TestMainModuleDoesNotHopThroughRealPackage(t *testing.T) {
	p, err := Load("../../testdata/binary.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, pk := range p.Packages {
		if pk.IsMainModule != (pk.Name == "github.com/example/demo") {
			t.Errorf("%s IsMainModule = %v", pk.Name, pk.IsMainModule)
		}
	}
}

func TestMainModuleHopsThroughDocumentRoot(t *testing.T) {
	doc := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	 "packages":[
	  {"SPDXID":"SPDXRef-DocumentRoot-Directory-.","name":"."},
	  {"SPDXID":"SPDXRef-app","name":"app"},
	  {"SPDXID":"SPDXRef-dep","name":"dep"}],
	 "relationships":[
	  {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-.","relationshipType":"DESCRIBES"},
	  {"spdxElementId":"SPDXRef-DocumentRoot-Directory-.","relatedSpdxElement":"SPDXRef-app","relationshipType":"CONTAINS"},
	  {"spdxElementId":"SPDXRef-app","relatedSpdxElement":"SPDXRef-dep","relationshipType":"CONTAINS"}]}`
	p := loadString(t, doc)
	by := pkgByName(p)
	if !by["app"].IsMainModule || by["dep"].IsMainModule || by["."].IsMainModule {
		t.Errorf("main flags: root=%v app=%v dep=%v", by["."].IsMainModule, by["app"].IsMainModule, by["dep"].IsMainModule)
	}
}
