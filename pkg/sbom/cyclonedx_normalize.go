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

	p.Context = detectContextCDX(doc, p)
	return p
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
	}

	// CycloneDX has a single license notion. Map it to LicenseConcluded because
	// that is the field most consumers read; leave LicenseDeclared empty so the
	// license-coverage report can show the declared/concluded asymmetry honestly.
	if expr := cdxLicenseExpr(c.Licenses); expr != "" {
		np.LicenseConcluded = expr
	} else {
		np.LicenseConcluded = NoAssertion
	}
	np.LicenseDeclared = NoAssertion

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

// detectContextCDX infers source vs binary for a CycloneDX BOM. CycloneDX rarely
// records this explicitly, so we use the primary component type and the presence
// of a stdlib component as heuristics.
func detectContextCDX(doc *CycloneDXDocument, p *Parsed) string {
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
