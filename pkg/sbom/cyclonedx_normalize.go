package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NormalizeCycloneDX converts a parsed CycloneDX document into the shared
// Parsed view used by the comparison engine. All format-specific quirks are
// resolved here so the rest of the tool never sees CycloneDX structures.
func NormalizeCycloneDX(doc *CycloneDXDocument) *Parsed {
	p := &Parsed{
		Relationships: nil,
		BySPDXID:      map[string]*NormalizedPackage{},
		CycloneDX:     doc,
	}
	p.ToolLabel, p.ToolName = cdxToolLabel(doc)

	// The primary component (metadata.component) is the main module. It is also a
	// package in its own right, so include it in the package set.
	mainRef := ""
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		mc := doc.Metadata.Component
		mainRef = componentKey(mc)
		np := normalizeCDXComponent(mc)
		np.IsMainModule = true
		p.Packages = append(p.Packages, np)
	}

	// Flatten nested components (CycloneDX allows components-within-components).
	var flatten func(comps []CDXComponent)
	flatten = func(comps []CDXComponent) {
		for i := range comps {
			c := &comps[i]
			np := normalizeCDXComponent(c)
			p.Packages = append(p.Packages, np)
			if len(c.Components) > 0 {
				flatten(c.Components)
			}
		}
	}
	flatten(doc.Components)

	// Index by SPDXID (we synthesize SPDXID = bom-ref for CycloneDX).
	for i := range p.Packages {
		p.BySPDXID[p.Packages[i].SPDXID] = &p.Packages[i]
	}

	// Convert the dependency graph into SPDX-style relationships so the dependency
	// analysis works unchanged. CycloneDX `ref dependsOn [a,b]` becomes
	// `ref DEPENDS_ON a`, `ref DEPENDS_ON b`.
	p.Relationships = cdxRelationships(doc, mainRef)

	// Document-level annotations.
	p.DocAnnotations = cdxDocAnnotations(doc)

	p.Meta = cdxDocMeta(doc)
	p.Context = detectContextCDX(doc, p)
	return p
}

// cdxDocMeta extracts document metadata (spec version, timestamp, authors,
// tools, lifecycle) from a CycloneDX BOM.
func cdxDocMeta(doc *CycloneDXDocument) DocMeta {
	m := DocMeta{DependencyDeclared: map[string]bool{}}
	m.Signed = len(doc.Signature) > 0 && string(doc.Signature) != "null"
	if doc.SpecVersion != "" {
		m.SpecVersion = "CycloneDX-" + doc.SpecVersion
	}
	if doc.SerialNumber != "" || doc.Version > 0 {
		m.DocVersion = fmt.Sprintf("%s#%d", doc.SerialNumber, doc.Version)
	}
	for _, d := range doc.Dependencies {
		if d.Ref != "" {
			m.DependencyDeclared[d.Ref] = true
		}
	}
	md := doc.Metadata
	if md == nil {
		return m
	}
	m.Created = md.Timestamp
	for _, a := range md.Authors {
		if a.Name != "" {
			m.Authors = append(m.Authors, a.Name)
		} else if a.Email != "" {
			m.Authors = append(m.Authors, a.Email)
		}
	}
	for _, org := range []*CDXOrg{md.Manufacturer, md.Manufacture, md.Supplier} {
		if org != nil && org.Name != "" && !containsStr(m.Authors, org.Name) {
			m.Authors = append(m.Authors, org.Name)
		}
	}
	addTool := func(name, version string) {
		if name == "" {
			return
		}
		label := name
		if version != "" {
			label = name + " " + version
			m.ToolVersions = append(m.ToolVersions, label)
		}
		m.Tools = append(m.Tools, label)
	}
	for _, t := range md.Tools.Tools {
		addTool(t.Name, t.Version)
	}
	for _, t := range md.Tools.Components {
		addTool(t.Name, t.Version)
	}
	for _, lc := range md.Lifecycles {
		if lc.Phase != "" {
			m.Lifecycle = lc.Phase
			break
		}
		if lc.Name != "" && m.Lifecycle == "" {
			m.Lifecycle = lc.Name
		}
	}
	return m
}

// lifecycleContext maps an explicitly declared generation context (CycloneDX
// lifecycle phase or SPDX 3 sbomType) to "source", "binary" or "" when the
// phase does not settle the question (e.g. "build").
func lifecycleContext(phase string) string {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "design", "pre-build", "source":
		return "source"
	case "post-build", "operations", "analyzed", "deployed", "runtime":
		return "binary"
	}
	return ""
}

// componentKey returns the stable key for a component: its bom-ref if present,
// otherwise its purl, otherwise name@version.
func componentKey(c *CDXComponent) string {
	if c.BOMRef != "" {
		return c.BOMRef
	}
	if c.PURL != "" {
		return c.PURL
	}
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

func normalizeCDXComponent(c *CDXComponent) NormalizedPackage {
	np := NormalizedPackage{
		SPDXID:   componentKey(c),
		Name:     cdxFullName(c),
		Version:  c.Version,
		PURL:     c.PURL,
		CPEs:     c.cdxResolveCPE(),
		Supplier: cdxSupplierName(c),
		// v1.6+ manufacturer/authors identify the component's creator.
		Originator: cdxProducerName(c),
	}
	np.OtherIDs = append(append(np.OtherIDs, c.OmniborID...), c.SWHID...)

	// CycloneDX 1.6+ marks each license as declared or concluded via
	// `acknowledgement`. Older BOMs have a single license notion, which is mapped
	// to LicenseConcluded (the field most consumers read); LicenseDeclared then
	// stays NOASSERTION so the license report shows the asymmetry honestly.
	np.LicenseDeclared, np.LicenseConcluded = cdxLicenses(c.Licenses)
	if np.LicenseDeclared == "" {
		np.LicenseDeclared = NoAssertion
	}
	if np.LicenseConcluded == "" {
		np.LicenseConcluded = NoAssertion
	}

	np.PURLType, np.ModulePath = parsePURL(np.PURL, np.Name)

	// Checksums.
	np.ChecksumNum = len(c.Hashes)
	for _, h := range c.Hashes {
		if cdxIsSHA256(h.Alg) && h.Content != "" {
			np.HasSHA256 = true
		}
	}

	// Scope: optional/excluded components are treated as non-runtime (test-ish).
	switch strings.ToLower(strings.TrimSpace(c.Scope)) {
	case "optional", "excluded":
		np.IsTestScoped = true
	}

	// Evidence + properties become annotations so the transparency report can
	// credit CycloneDX producers that ship identity evidence / tool metadata.
	np.Annotations = cdxComponentAnnotations(c)

	if isStdlib(np.Name, np.PURL) {
		np.IsStdlib = true
	}
	return np
}

// cdxFullName joins group + name the way CycloneDX expects for display (e.g.
// Maven group:artifact), but only when a group is present.
func cdxFullName(c *CDXComponent) string {
	if c.Group != "" && !strings.Contains(c.Name, c.Group) {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

func cdxIsSHA256(alg string) bool {
	a := strings.ToUpper(strings.TrimSpace(alg))
	a = strings.ReplaceAll(a, "-", "")
	a = strings.ReplaceAll(a, "_", "")
	return a == "SHA256"
}

// cdxComponentAnnotations synthesizes SPDX-style annotations from CycloneDX
// evidence and properties so downstream richness scoring has something to read.
func cdxComponentAnnotations(c *CDXComponent) []Annotation {
	var out []Annotation
	if c.Evidence != nil && len(c.Evidence.Identity) > 0 {
		raw := strings.TrimSpace(string(c.Evidence.Identity))
		if raw != "" && raw != "null" {
			out = append(out, Annotation{
				AnnotationType: "OTHER",
				Comment:        "evidence.identity: " + raw,
			})
		}
	}
	for _, prop := range c.Properties {
		if prop.Name == "" {
			continue
		}
		out = append(out, Annotation{
			AnnotationType: "OTHER",
			Comment:        prop.Name + ": " + prop.Value,
		})
	}
	return out
}

// cdxRelationships builds SPDX-style relationships from the CycloneDX dependency
// graph. The primary component's dependency edges double as the DESCRIBES anchor.
func cdxRelationships(doc *CycloneDXDocument, mainRef string) []Relationship {
	var rels []Relationship
	if mainRef != "" {
		rels = append(rels, Relationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelatedSPDXElement: mainRef,
			RelationshipType:   "DESCRIBES",
		})
	}
	for _, d := range doc.Dependencies {
		for _, on := range d.DependsOn {
			rels = append(rels, Relationship{
				SPDXElementID:      d.Ref,
				RelatedSPDXElement: on,
				RelationshipType:   "DEPENDS_ON",
			})
		}
	}
	return rels
}

func cdxDocAnnotations(doc *CycloneDXDocument) []Annotation {
	var out []Annotation
	for _, a := range doc.Annotations {
		if a.Text == "" {
			continue
		}
		out = append(out, Annotation{
			AnnotationType: "OTHER",
			Comment:        a.Text,
		})
	}
	for _, comp := range doc.Compositions {
		if comp.Aggregate != "" {
			out = append(out, Annotation{
				AnnotationType: "OTHER",
				Comment:        "composition.aggregate: " + comp.Aggregate,
			})
		}
	}
	return out
}

// cdxToolLabel derives a "name vX.Y.Z" label from CycloneDX metadata.tools,
// supporting both the legacy array form and the v1.5 components form.
func cdxToolLabel(doc *CycloneDXDocument) (label, name string) {
	if doc.Metadata == nil {
		return "cyclonedx-tool", "cyclonedx"
	}
	tf := doc.Metadata.Tools
	// Legacy array form.
	for _, t := range tf.Tools {
		if t.Name == "" {
			continue
		}
		if t.Version != "" {
			return t.Name + " v" + strings.TrimPrefix(t.Version, "v"), t.Name
		}
		return t.Name, t.Name
	}
	// v1.5 components form.
	for _, comp := range tf.Components {
		if comp.Name == "" {
			continue
		}
		if comp.Version != "" {
			return comp.Name + " v" + strings.TrimPrefix(comp.Version, "v"), comp.Name
		}
		return comp.Name, comp.Name
	}
	return "cyclonedx-tool", "cyclonedx"
}

// detectContextCDX infers source vs binary for a CycloneDX BOM. A declared
// metadata.lifecycles phase wins; otherwise the primary component type and the
// presence of a stdlib component are used as heuristics.
func detectContextCDX(doc *CycloneDXDocument, p *Parsed) string {
	// An explicit lifecycle phase (v1.5+) is the most reliable signal.
	if ctx := lifecycleContext(p.Meta.Lifecycle); ctx != "" {
		return ctx
	}
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		switch strings.ToLower(doc.Metadata.Component.Type) {
		case "application", "container", "firmware", "operating-system":
			// A built artifact described directly.
			for i := range p.Packages {
				if p.Packages[i].IsStdlib {
					return "binary"
				}
			}
		case "library":
			// Often a source/module scan.
		}
	}
	for i := range p.Packages {
		if p.Packages[i].IsStdlib {
			return "binary"
		}
	}
	// Tool hints.
	joined := strings.ToLower(p.ToolName)
	if strings.Contains(joined, "gomod") || strings.Contains(joined, "cyclonedx-py") ||
		strings.Contains(joined, "cdxgen") {
		return "source"
	}
	return "unknown"
}

// parseCycloneDXJSON decodes CycloneDX JSON bytes into a document.
func parseCycloneDXJSON(data []byte) (*CycloneDXDocument, error) {
	doc := &CycloneDXDocument{}
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("parse CycloneDX JSON: %w", err)
	}
	if doc.BOMFormat == "" && doc.SpecVersion == "" {
		return nil, fmt.Errorf("not a CycloneDX document (missing bomFormat/specVersion)")
	}
	return doc, nil
}
