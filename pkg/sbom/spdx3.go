package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// SPDX 3 JSON-LD support.
//
// SPDX 3 replaces the document-centric SPDX 2 layout with a flat JSON-LD
// "@graph" of typed elements that reference each other by IRI:
//
//   - software_Package (also ai_AIPackage, dataset_DatasetPackage) carry
//     name, software_packageVersion, software_packageUrl, externalIdentifier
//     (packageUrl / cpe23 / ...), verifiedUsing hashes and suppliedBy /
//     originatedBy agent references;
//   - licenses are separate elements linked by hasDeclaredLicense /
//     hasConcludedLicense relationships;
//   - dependencies are Relationship / LifecycleScopedRelationship elements with
//     a "from" IRI, a "to" IRI list and a camelCase relationshipType;
//   - provenance lives in shared CreationInfo blank nodes (createdBy agents,
//     createdUsing tools) and the SpdxDocument / software_Sbom rootElement.
//
// Rather than teach the comparison engine a second graph model, the graph is
// converted into the SPDX 2-shaped Document and normalized with the same code
// as SPDX 2, so every analyzer behaves identically across SPDX versions.

// spdx3Graph is a flattened index of SPDX 3 elements. Inline element objects
// that carry an identifier are hoisted into the index and replaced by their IRI
// so references can always be resolved by ID.
type spdx3Graph struct {
	elems []map[string]any
	byID  map[string]map[string]any
}

// parseSPDX3 decodes SPDX 3 JSON-LD bytes into a normalized Parsed view.
func parseSPDX3(data []byte) (*Parsed, error) {
	var root any
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse SPDX 3 JSON-LD: %w", err)
	}
	g := &spdx3Graph{byID: map[string]map[string]any{}}
	switch v := root.(type) {
	case map[string]any:
		if graph, ok := v["@graph"].([]any); ok {
			for _, e := range graph {
				g.add(e)
			}
		} else {
			// A single top-level element without an @graph wrapper.
			delete(v, "@context")
			g.add(v)
		}
	case []any:
		for _, e := range v {
			g.add(e)
		}
	}
	if len(g.elems) == 0 {
		return nil, fmt.Errorf("not an SPDX 3 document (no @graph elements)")
	}

	doc, sbomType := g.toDocument()
	p := Normalize(doc)
	if sbomType != "" {
		p.Meta.Lifecycle = sbomType
		if ctx := lifecycleContext(sbomType); ctx != "" {
			p.Context = ctx
		}
	}
	return p, nil
}

func (g *spdx3Graph) add(v any) {
	res := g.flatten(v)
	// Top-level elements without an identifier are still graph members.
	if m, ok := res.(map[string]any); ok && s3Type(m) != "" {
		g.elems = append(g.elems, m)
	}
}

// flatten walks a decoded JSON value, registering every typed object that has
// an identifier and replacing it by its IRI in the parent.
func (g *spdx3Graph) flatten(v any) any {
	switch x := v.(type) {
	case map[string]any:
		// Sorted keys keep the registration order of nested inline elements
		// (and thus package order) deterministic.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			x[k] = g.flatten(x[k])
		}
		if id := s3ID(x); id != "" && s3Type(x) != "" {
			if _, dup := g.byID[id]; !dup {
				g.byID[id] = x
				g.elems = append(g.elems, x)
			}
			return id
		}
		return x
	case []any:
		for i := range x {
			x[i] = g.flatten(x[i])
		}
		return x
	}
	return v
}

func s3ID(m map[string]any) string {
	if id, ok := m["spdxId"].(string); ok && id != "" {
		return id
	}
	if id, ok := m["@id"].(string); ok {
		return id
	}
	return ""
}

// s3Type returns the compact SPDX 3 type name ("software_Package",
// "Relationship", ...), converting full IRIs such as
// "https://spdx.org/rdf/3.0.1/terms/Software/Package" to the compact form.
func s3Type(m map[string]any) string {
	t, _ := m["type"].(string)
	if t == "" {
		t, _ = m["@type"].(string)
	}
	t = strings.TrimPrefix(t, "spdx:")
	if i := strings.Index(t, "/terms/"); i >= 0 {
		parts := strings.SplitN(t[i+len("/terms/"):], "/", 2)
		if len(parts) == 2 {
			if parts[0] == "Core" {
				return parts[1]
			}
			return strings.ToLower(parts[0]) + "_" + parts[1]
		}
	}
	return t
}

func s3Str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				return s
			}
		}
	}
	return ""
}

// s3Strs returns a string or string-array property as a slice.
func s3Strs(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// s3Objs returns an object or object-array property, resolving IRI references
// through the graph index.
func (g *spdx3Graph) s3Objs(m map[string]any, key string) []map[string]any {
	var out []map[string]any
	add := func(x any) {
		switch o := x.(type) {
		case map[string]any:
			out = append(out, o)
		case string:
			if e := g.byID[o]; e != nil {
				out = append(out, e)
			}
		}
	}
	switch v := m[key].(type) {
	case []any:
		for _, x := range v {
			add(x)
		}
	default:
		add(v)
	}
	return out
}

func isSPDX3Package(t string) bool {
	switch t {
	case "software_Package", "ai_AIPackage", "dataset_DatasetPackage":
		return true
	}
	return false
}

// toDocument converts the element graph into an SPDX 2-shaped Document. It
// also returns the declared software_sbomType (generation context), if any.
func (g *spdx3Graph) toDocument() (*Document, string) {
	doc := &Document{SPDXID: "SPDXRef-DOCUMENT"}

	var spdxDoc map[string]any
	var sboms []map[string]any
	var rels, anns []map[string]any
	for _, e := range g.elems {
		switch t := s3Type(e); {
		case t == "SpdxDocument":
			if spdxDoc == nil {
				spdxDoc = e
			}
		case t == "software_Sbom":
			sboms = append(sboms, e)
		case t == "Annotation":
			anns = append(anns, e)
		case strings.HasSuffix(t, "Relationship") && !strings.HasPrefix(t, "security_"):
			rels = append(rels, e)
		}
	}

	// Provenance: the document's CreationInfo (falling back to the SBOM or the
	// first element that has one).
	ciOwner := spdxDoc
	if ciOwner == nil && len(sboms) > 0 {
		ciOwner = sboms[0]
	}
	ci := g.creationInfo(ciOwner)
	if ci == nil {
		for _, e := range g.elems {
			if ci = g.creationInfo(e); ci != nil {
				break
			}
		}
	}
	doc.SPDXVersion = "SPDX-3.0"
	if ci != nil {
		if v := s3Str(ci, "specVersion"); v != "" {
			doc.SPDXVersion = "SPDX-" + v
		}
		doc.CreationInfo.Created = s3Str(ci, "created")
		for _, t := range g.s3Objs(ci, "createdUsing") {
			if name := s3Str(t, "name"); name != "" {
				doc.CreationInfo.Creators = append(doc.CreationInfo.Creators, "Tool: "+name)
			}
		}
		for _, a := range s3Strs(ci, "createdBy") {
			if label := g.agentLabel(a); label != "" {
				doc.CreationInfo.Creators = append(doc.CreationInfo.Creators, label)
			}
		}
	}
	if spdxDoc != nil {
		doc.Name = s3Str(spdxDoc, "name")
		doc.DocumentNamespace = s3ID(spdxDoc)
	}

	// Annotations, keyed by subject.
	pkgAnns := map[string][]Annotation{}
	docIDs := map[string]bool{}
	if spdxDoc != nil {
		docIDs[s3ID(spdxDoc)] = true
	}
	for _, s := range sboms {
		docIDs[s3ID(s)] = true
	}
	for _, a := range anns {
		ann := Annotation{
			AnnotationType: strings.ToUpper(s3Str(a, "annotationType")),
			Comment:        s3Str(a, "statement"),
		}
		if c := g.creationInfo(a); c != nil {
			ann.AnnotationDate = s3Str(c, "created")
		}
		subj := s3Str(a, "subject")
		if docIDs[subj] {
			doc.Annotations = append(doc.Annotations, ann)
		} else {
			pkgAnns[subj] = append(pkgAnns[subj], ann)
		}
	}

	// Relationships: license links become package fields; everything else is
	// kept as an SPDX 2-style typed edge.
	declared := map[string][]string{}
	concluded := map[string][]string{}
	for _, r := range rels {
		relType := s3Str(r, "relationshipType")
		from := s3Str(r, "from")
		tos := s3Strs(r, "to")
		switch relType {
		case "hasDeclaredLicense", "hasConcludedLicense":
			for _, to := range tos {
				expr := g.licenseExpr(to, 0)
				if expr == "" {
					continue
				}
				if relType == "hasDeclaredLicense" {
					declared[from] = append(declared[from], expr)
				} else {
					concluded[from] = append(concluded[from], expr)
				}
			}
			continue
		}
		scope := strings.ToLower(s3Str(r, "scope"))
		reverse := ""
		if relType == "dependsOn" {
			switch scope {
			case "test":
				reverse = "TEST_DEPENDENCY_OF"
			case "development":
				reverse = "DEV_DEPENDENCY_OF"
			case "build":
				reverse = "BUILD_DEPENDENCY_OF"
			}
		}
		for _, to := range tos {
			if reverse != "" {
				// "A dependsOn B (scope test)" == SPDX 2 "B TEST_DEPENDENCY_OF A".
				doc.Relationships = append(doc.Relationships, Relationship{
					SPDXElementID: to, RelatedSPDXElement: from, RelationshipType: reverse,
				})
				continue
			}
			doc.Relationships = append(doc.Relationships, Relationship{
				SPDXElementID: from, RelatedSPDXElement: to, RelationshipType: camelToUpperSnake(relType),
			})
		}
	}

	// Packages.
	for _, e := range g.elems {
		if !isSPDX3Package(s3Type(e)) {
			continue
		}
		id := s3ID(e)
		name := s3Str(e, "name")
		if name == "" {
			// name is optional in SPDX 3 (e.g. AI/dataset packages); fall back to
			// the IRI fragment so the package stays identifiable in reports.
			name = iriLastSegment(id)
		}
		pkg := Package{
			SPDXID:           id,
			Name:             name,
			VersionInfo:      s3Str(e, "software_packageVersion"),
			DownloadLocation: s3Str(e, "software_downloadLocation"),
			SourceInfo:       s3Str(e, "software_sourceInfo"),
			CopyrightText:    s3Str(e, "software_copyrightText"),
			PrimaryPurpose:   s3Str(e, "software_primaryPurpose"),
			Supplier:         g.agentLabel(s3Str(e, "suppliedBy")),
			Originator:       g.agentLabel(s3Str(e, "originatedBy")),
			LicenseDeclared:  joinLicenses(declared[id]),
			LicenseConcluded: joinLicenses(concluded[id]),
			Annotations:      pkgAnns[id],
		}
		if purl := s3Str(e, "software_packageUrl"); purl != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, ExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: purl,
			})
		}
		for _, xi := range g.s3Objs(e, "externalIdentifier") {
			if ref, ok := s3ExternalIdentifier(xi); ok {
				pkg.ExternalRefs = append(pkg.ExternalRefs, ref)
			}
		}
		for _, ci := range g.s3Objs(e, "software_contentIdentifier") {
			val := s3Str(ci, "software_contentIdentifierValue")
			switch s3Str(ci, "software_contentIdentifierType") {
			case "gitoid":
				pkg.ExternalRefs = append(pkg.ExternalRefs, ExternalRef{ReferenceCategory: "PERSISTENT-ID", ReferenceType: "gitoid", ReferenceLocator: val})
			case "swhid":
				pkg.ExternalRefs = append(pkg.ExternalRefs, ExternalRef{ReferenceCategory: "PERSISTENT-ID", ReferenceType: "swh", ReferenceLocator: val})
			}
		}
		for _, h := range g.s3Objs(e, "verifiedUsing") {
			if s3Type(h) != "Hash" {
				continue
			}
			pkg.Checksums = append(pkg.Checksums, Checksum{
				Algorithm:     spdx3HashAlg(s3Str(h, "algorithm")),
				ChecksumValue: s3Str(h, "hashValue"),
			})
		}
		doc.Packages = append(doc.Packages, pkg)
	}

	// Main module(s): the packages the document / SBOM declare as root
	// elements, resolving through nested software_Sbom / Bom / Bundle roots.
	isPkg := map[string]bool{}
	for _, pk := range doc.Packages {
		isPkg[pk.SPDXID] = true
	}
	seen := map[string]bool{}
	var collect func(ids []string, depth int)
	collect = func(ids []string, depth int) {
		for _, id := range ids {
			if seen[id] || depth > 4 {
				continue
			}
			seen[id] = true
			if isPkg[id] {
				doc.DocumentDescribes = append(doc.DocumentDescribes, id)
				continue
			}
			if e := g.byID[id]; e != nil {
				collect(s3Strs(e, "rootElement"), depth+1)
			}
		}
	}
	if spdxDoc != nil {
		collect(s3Strs(spdxDoc, "rootElement"), 0)
	}
	for _, s := range sboms {
		collect(s3Strs(s, "rootElement"), 0)
	}

	sbomType := ""
	for _, s := range sboms {
		if ts := s3Strs(s, "software_sbomType"); len(ts) > 0 {
			sbomType = ts[0]
			break
		}
	}
	return doc, sbomType
}

// creationInfo resolves an element's CreationInfo (blank-node reference or
// inline object).
func (g *spdx3Graph) creationInfo(e map[string]any) map[string]any {
	if e == nil {
		return nil
	}
	switch v := e["creationInfo"].(type) {
	case map[string]any:
		return v
	case string:
		return g.byID[v]
	}
	return nil
}

// agentLabel renders an agent reference in SPDX 2 creator/supplier syntax
// ("Organization: X", "Person: Y", "Tool: Z").
func (g *spdx3Graph) agentLabel(ref string) string {
	if ref == "" {
		return ""
	}
	e := g.byID[ref]
	if e == nil {
		// External agent not defined in this document: use the IRI's last
		// segment as a best-effort name.
		if name := iriLastSegment(ref); name != "" {
			return "Organization: " + name
		}
		return ""
	}
	name := s3Str(e, "name")
	if name == "" {
		name = iriLastSegment(ref)
	}
	switch s3Type(e) {
	case "Person":
		return "Person: " + name
	case "Tool", "SoftwareAgent":
		return "Tool: " + name
	default:
		return "Organization: " + name
	}
}

// s3ExternalIdentifier maps an SPDX 3 ExternalIdentifier onto an SPDX 2
// external reference.
func s3ExternalIdentifier(xi map[string]any) (ExternalRef, bool) {
	id := s3Str(xi, "identifier")
	if id == "" {
		return ExternalRef{}, false
	}
	switch s3Str(xi, "externalIdentifierType") {
	case "packageUrl":
		return ExternalRef{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: id}, true
	case "cpe23":
		return ExternalRef{ReferenceCategory: "SECURITY", ReferenceType: "cpe23Type", ReferenceLocator: id}, true
	case "cpe22":
		return ExternalRef{ReferenceCategory: "SECURITY", ReferenceType: "cpe22Type", ReferenceLocator: id}, true
	case "swid":
		return ExternalRef{ReferenceCategory: "PERSISTENT-ID", ReferenceType: "swid", ReferenceLocator: id}, true
	case "gitoid":
		return ExternalRef{ReferenceCategory: "PERSISTENT-ID", ReferenceType: "gitoid", ReferenceLocator: id}, true
	case "swhid":
		return ExternalRef{ReferenceCategory: "PERSISTENT-ID", ReferenceType: "swh", ReferenceLocator: id}, true
	}
	return ExternalRef{}, false
}

// spdx3HashAlg converts SPDX 3 hash algorithm names ("sha256", "sha3_256",
// "blake2b256") to SPDX 2 spelling ("SHA256", "SHA3-256", "BLAKE2B256").
func spdx3HashAlg(alg string) string {
	return strings.ReplaceAll(strings.ToUpper(alg), "_", "-")
}

// licenseExpr renders a license element (or a reference to one) as an SPDX
// license expression string.
func (g *spdx3Graph) licenseExpr(v any, depth int) string {
	if depth > 16 {
		return ""
	}
	switch x := v.(type) {
	case map[string]any:
		return g.licenseFromElem(x, depth)
	case string:
		if e := g.byID[x]; e != nil {
			return g.licenseFromElem(e, depth)
		}
		return licenseFromIRI(x)
	}
	return ""
}

func (g *spdx3Graph) licenseFromElem(e map[string]any, depth int) string {
	switch s3Type(e) {
	case "simplelicensing_LicenseExpression":
		return s3Str(e, "simplelicensing_licenseExpression")
	case "expandedlicensing_ConjunctiveLicenseSet":
		return g.joinMembers(e, " AND ", depth)
	case "expandedlicensing_DisjunctiveLicenseSet":
		return g.joinMembers(e, " OR ", depth)
	case "expandedlicensing_OrLaterOperator":
		if l := g.licenseExpr(e["expandedlicensing_subjectLicense"], depth+1); l != "" {
			return l + "+"
		}
		return ""
	case "expandedlicensing_WithAdditionOperator":
		l := g.licenseExpr(e["expandedlicensing_subjectExtendableLicense"], depth+1)
		a := g.licenseExpr(e["expandedlicensing_subjectAddition"], depth+1)
		if l != "" && a != "" {
			return l + " WITH " + a
		}
		return l
	case "expandedlicensing_NoAssertionLicense":
		return NoAssertion
	case "expandedlicensing_NoneLicense":
		return None
	}
	return licenseFromIRI(s3ID(e))
}

func (g *spdx3Graph) joinMembers(e map[string]any, op string, depth int) string {
	var parts []string
	members, _ := e["expandedlicensing_member"].([]any)
	for _, m := range members {
		l := g.licenseExpr(m, depth+1)
		if l == "" {
			continue
		}
		if strings.Contains(l, " ") {
			l = "(" + l + ")"
		}
		parts = append(parts, l)
	}
	return strings.Join(parts, op)
}

// licenseFromIRI derives a license identifier from a license IRI, e.g.
// "http://spdx.org/licenses/MIT" -> "MIT" and
// ".../ExpandedLicensing/NoAssertionLicense" -> "NOASSERTION".
func licenseFromIRI(iri string) string {
	switch {
	case iri == "":
		return ""
	case strings.HasSuffix(iri, "NoAssertionLicense"):
		return NoAssertion
	case strings.HasSuffix(iri, "NoneLicense"):
		return None
	}
	return iriLastSegment(iri)
}

func iriLastSegment(iri string) string {
	iri = strings.TrimRight(iri, "/#")
	if i := strings.LastIndexAny(iri, "/#"); i >= 0 {
		return iri[i+1:]
	}
	return iri
}

// joinLicenses combines multiple license relationships into one expression,
// defaulting to NOASSERTION when there are none.
func joinLicenses(exprs []string) string {
	switch len(exprs) {
	case 0:
		return NoAssertion
	case 1:
		return exprs[0]
	}
	sorted := append([]string(nil), exprs...)
	sort.Strings(sorted)
	for i, e := range sorted {
		if strings.Contains(e, " ") {
			sorted[i] = "(" + e + ")"
		}
	}
	return strings.Join(sorted, " AND ")
}

// camelToUpperSnake converts an SPDX 3 relationshipType ("dependsOn",
// "hasStaticLink") to SPDX 2 style ("DEPENDS_ON", "HAS_STATIC_LINK").
func camelToUpperSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}
