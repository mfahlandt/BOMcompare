package compare

import (
	"strings"

	"github.com/seebom-labs/BOMHort/BOMcompare/pkg/sbom"
)

// CISAMinimumElementsRef identifies the baseline checked by analyzeMinimumElements.
const CISAMinimumElementsRef = "CISA 2026 Minimum Elements for a Software Bill of Materials"

// Minimum-element statuses.
const (
	MinPass       = "pass"       // element present for the document / every component
	MinWarn       = "warn"       // every component covered, some only as a declared unknown (NOASSERTION)
	MinFail       = "fail"       // element missing (for at least one component)
	MinUnverified = "unverified" // cannot be judged from the document alone
)

// MinimumElements is an informational compliance view of each SBOM against the
// CISA 2026 minimum elements. It does not feed the weighted scorecard.
type MinimumElements struct {
	Reference string          `json:"reference"`
	Rows      []MinElementRow `json:"rows"`
	PassedA   int             `json:"passedA"`
	PassedB   int             `json:"passedB"`
	Total     int             `json:"total"`
}

// MinElementRow is one minimum element evaluated on both SBOMs.
type MinElementRow struct {
	Element string           `json:"element"`
	Scope   string           `json:"scope"` // "document" or "component"
	A       MinElementResult `json:"a"`
	B       MinElementResult `json:"b"`
}

// MinElementResult is the outcome for one SBOM. Document-level elements carry
// the observed Value; component-level elements carry coverage counts.
type MinElementResult struct {
	Status  string  `json:"status"`
	Value   string  `json:"value,omitempty"`
	Present int     `json:"present,omitempty"`
	Unknown int     `json:"unknown,omitempty"`
	Total   int     `json:"total,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
}

type docCheck struct {
	element string
	eval    func(p *sbom.Parsed) MinElementResult
}

// componentCheck classifies a package as having the element (present), stating
// it as unknown (unknown), or omitting it.
type componentCheck struct {
	element string
	eval    func(p *sbom.Parsed, pkg *sbom.NormalizedPackage, deps map[string]bool) (present, unknown bool)
}

var minDocChecks = []docCheck{
	{"SBOM Author", func(p *sbom.Parsed) MinElementResult { return docValue(strings.Join(p.Meta.Authors, ", ")) }},
	{"Author Signature", func(p *sbom.Parsed) MinElementResult {
		if p.Meta.Signed {
			return MinElementResult{Status: MinPass, Value: "enveloped signature"}
		}
		return MinElementResult{Status: MinUnverified, Value: "not signed in-document"}
	}},
	{"Data Format Name", func(p *sbom.Parsed) MinElementResult { return docValue(formatName(p.Format)) }},
	{"Data Format Version", func(p *sbom.Parsed) MinElementResult { return docValue(p.Meta.SpecVersion) }},
	{"Generation Context", func(p *sbom.Parsed) MinElementResult {
		if p.Meta.Lifecycle != "" {
			return docValue(p.Meta.Lifecycle)
		}
		r := MinElementResult{Status: MinFail, Value: "not declared"}
		if p.Context != "" && p.Context != "unknown" {
			r.Value += " (inferred: " + p.Context + ")"
		}
		return r
	}},
	{"Timestamp", func(p *sbom.Parsed) MinElementResult { return docValue(p.Meta.Created) }},
	{"Tool Name", func(p *sbom.Parsed) MinElementResult { return docValue(strings.Join(p.Meta.Tools, ", ")) }},
	{"Tool Version", func(p *sbom.Parsed) MinElementResult { return docValue(strings.Join(p.Meta.ToolVersions, ", ")) }},
	{"SBOM Version", func(p *sbom.Parsed) MinElementResult { return docValue(p.Meta.DocVersion) }},
}

var minComponentChecks = []componentCheck{
	{"Component Producer", func(p *sbom.Parsed, pkg *sbom.NormalizedPackage, _ map[string]bool) (bool, bool) {
		if resolved(pkg.Supplier) || resolved(pkg.Originator) {
			return true, false
		}
		return false, declaredUnknown(p, pkg.Supplier) || declaredUnknown(p, pkg.Originator)
	}},
	{"Component Name", func(_ *sbom.Parsed, pkg *sbom.NormalizedPackage, _ map[string]bool) (bool, bool) {
		return strings.TrimSpace(pkg.Name) != "", false
	}},
	{"Component Version", func(p *sbom.Parsed, pkg *sbom.NormalizedPackage, _ map[string]bool) (bool, bool) {
		return resolved(pkg.Version), declaredUnknown(p, pkg.Version)
	}},
	{"Software Identifiers", func(_ *sbom.Parsed, pkg *sbom.NormalizedPackage, _ map[string]bool) (bool, bool) {
		return pkg.PURL != "" || len(pkg.CPEs) > 0 || len(pkg.OtherIDs) > 0, false
	}},
	{"Component Hash (value + algorithm)", func(_ *sbom.Parsed, pkg *sbom.NormalizedPackage, _ map[string]bool) (bool, bool) {
		return pkg.ChecksumNum > 0, false
	}},
	{"License", func(p *sbom.Parsed, pkg *sbom.NormalizedPackage, _ map[string]bool) (bool, bool) {
		if effectiveLicense(pkg) != "" {
			return true, false
		}
		return false, declaredUnknown(p, pkg.LicenseConcluded) || declaredUnknown(p, pkg.LicenseDeclared)
	}},
	{"Dependency Relationship", func(_ *sbom.Parsed, pkg *sbom.NormalizedPackage, deps map[string]bool) (bool, bool) {
		return deps[pkg.SPDXID], false
	}},
}

func analyzeMinimumElements(a, b *sbom.Parsed) MinimumElements {
	m := MinimumElements{Reference: CISAMinimumElementsRef}
	for _, c := range minDocChecks {
		m.Rows = append(m.Rows, MinElementRow{Element: c.element, Scope: "document", A: c.eval(a), B: c.eval(b)})
	}
	depsA, depsB := dependencyParticipants(a), dependencyParticipants(b)
	for _, c := range minComponentChecks {
		m.Rows = append(m.Rows, MinElementRow{
			Element: c.element,
			Scope:   "component",
			A:       componentCoverage(a, depsA, c),
			B:       componentCoverage(b, depsB, c),
		})
	}
	m.Total = len(m.Rows)
	for _, r := range m.Rows {
		if r.A.Status == MinPass {
			m.PassedA++
		}
		if r.B.Status == MinPass {
			m.PassedB++
		}
	}
	return m
}

func componentCoverage(p *sbom.Parsed, deps map[string]bool, c componentCheck) MinElementResult {
	r := MinElementResult{Total: len(p.Packages)}
	for i := range p.Packages {
		present, unknown := c.eval(p, &p.Packages[i], deps)
		switch {
		case present:
			r.Present++
		case unknown:
			r.Unknown++
		}
	}
	r.Rate = pct(r.Present, r.Total)
	switch {
	case r.Total == 0 || r.Present+r.Unknown < r.Total:
		r.Status = MinFail
	case r.Unknown > 0:
		r.Status = MinWarn
	default:
		r.Status = MinPass
	}
	return r
}

// dependencyParticipants returns the IDs of elements that take part in at
// least one dependency edge, or whose (possibly empty) dependency set was
// declared explicitly (CycloneDX dependencies[].ref).
func dependencyParticipants(p *sbom.Parsed) map[string]bool {
	out := map[string]bool{}
	for _, r := range p.Relationships {
		if IsDependencyEdge(r.RelationshipType) {
			out[r.SPDXElementID] = true
			out[r.RelatedSPDXElement] = true
		}
	}
	for id := range p.Meta.DependencyDeclared {
		out[id] = true
	}
	return out
}

func docValue(v string) MinElementResult {
	if strings.TrimSpace(v) == "" {
		return MinElementResult{Status: MinFail}
	}
	return MinElementResult{Status: MinPass, Value: v}
}

// declaredUnknown reports an explicit NOASSERTION/NONE. Only SPDX has these
// tokens (SPDX 2.3 and 3.0 imply NOASSERTION for absent license fields);
// CycloneDX normalization fills them in for absent values, which are omissions.
func declaredUnknown(p *sbom.Parsed, s string) bool {
	if formatName(p.Format) != "SPDX" {
		return false
	}
	s = strings.TrimSpace(s)
	return strings.EqualFold(s, sbom.NoAssertion) || strings.EqualFold(s, sbom.None)
}

func formatName(format string) string {
	switch format {
	case sbom.FormatSPDXJSON, sbom.FormatSPDXTagValue, sbom.FormatSPDX3JSONLD:
		return "SPDX"
	case sbom.FormatCycloneDXJSON, sbom.FormatCycloneDXXML:
		return "CycloneDX"
	}
	return ""
}
