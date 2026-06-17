package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Sentinel license/field values used across SPDX.
const (
	NoAssertion = "NOASSERTION"
	None        = "NONE"
)

// Parsed is a normalized, comparison-friendly view of an SPDX document. It is
// derived once from a Document so the comparison engine never has to re-walk raw
// SPDX structures.
type Parsed struct {
	// Source identification.
	FilePath  string
	ToolLabel string // e.g. "mikebom v0.1.0-alpha.47" or "syft v1.42.3"
	ToolName  string // e.g. "mikebom"
	Context   string // "source", "binary", or "unknown"

	// Normalized package set, keyed by SPDXID for relationship resolution.
	Packages []NormalizedPackage
	BySPDXID map[string]*NormalizedPackage

	// Raw graph + document annotations.
	Relationships  []Relationship
	DocAnnotations []Annotation

	// Format identifies the source serialization: "spdx-json",
	// "spdx-tagvalue", "cyclonedx-json" or "cyclonedx-xml".
	Format string

	// Exactly one of Raw / CycloneDX is set, depending on Format.
	Raw       *Document
	CycloneDX *CycloneDXDocument
}

// Format identifiers returned by DetectFormat and stored on Parsed.Format.
const (
	FormatSPDXJSON      = "spdx-json"
	FormatSPDXTagValue  = "spdx-tagvalue"
	FormatCycloneDXJSON = "cyclonedx-json"
	FormatCycloneDXXML  = "cyclonedx-xml"
	FormatUnknown       = "unknown"
)

// NormalizedPackage flattens the SPDX fields that matter for quality comparison.
type NormalizedPackage struct {
	SPDXID  string
	Name    string
	Version string

	// Identity.
	PURL       string   // primary purl (first PACKAGE-MANAGER purl ref)
	PURLType   string   // e.g. "golang", "generic", "npm"
	ModulePath string   // best-effort module path for cross-type matching
	CPEs       []string // all CPE 2.3 locators

	// License.
	LicenseDeclared  string
	LicenseConcluded string

	// Attribution / integrity.
	Supplier    string
	HasSHA256   bool
	ChecksumNum int

	// Scope.
	IsTestScoped bool // detected via TEST_DEPENDENCY_OF or lifecycle annotation

	// Transparency.
	Annotations []Annotation

	// Flags.
	IsMainModule bool
	IsStdlib     bool
}

// Load reads a file, auto-detects its SBOM format and returns a normalized
// Parsed view. Supported formats: SPDX JSON, SPDX tag-value, CycloneDX JSON and
// CycloneDX XML.
func Load(path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	format := DetectFormat(data)
	p, err := loadFormat(format, data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Format = format
	p.FilePath = path
	return p, nil
}

// loadFormat dispatches to the correct parser/normalizer for a detected format.
func loadFormat(format string, data []byte, path string) (*Parsed, error) {
	switch format {
	case FormatSPDXJSON:
		doc := &Document{}
		if err := json.Unmarshal(data, doc); err != nil {
			return nil, fmt.Errorf("parse as SPDX JSON: %w", err)
		}
		if doc.SPDXVersion == "" {
			return nil, fmt.Errorf("missing spdxVersion (not an SPDX document?)")
		}
		return Normalize(doc), nil
	case FormatSPDXTagValue:
		doc, err := parseSPDXTagValue(data)
		if err != nil {
			return nil, err
		}
		return Normalize(doc), nil
	case FormatCycloneDXJSON:
		doc, err := parseCycloneDXJSON(data)
		if err != nil {
			return nil, err
		}
		return NormalizeCycloneDX(doc), nil
	case FormatCycloneDXXML:
		doc, err := parseCycloneDXXML(data)
		if err != nil {
			return nil, err
		}
		return NormalizeCycloneDX(doc), nil
	default:
		return nil, fmt.Errorf("unrecognized SBOM format (not SPDX JSON/tag-value or CycloneDX JSON/XML)")
	}
}

// LoadSPDXJSON parses bytes as SPDX JSON regardless of detection.
func LoadSPDXJSON(path string) (*Parsed, error) {
	return loadExplicit(FormatSPDXJSON, path)
}

// LoadSPDXTagValue parses a file as SPDX tag-value regardless of detection.
func LoadSPDXTagValue(path string) (*Parsed, error) {
	return loadExplicit(FormatSPDXTagValue, path)
}

// LoadCycloneDX parses a file as CycloneDX, auto-selecting JSON vs XML by
// sniffing the first non-whitespace byte.
func LoadCycloneDX(path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	format := FormatCycloneDXJSON
	if b := firstNonSpace(data); b == '<' {
		format = FormatCycloneDXXML
	}
	p, err := loadFormat(format, data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Format = format
	p.FilePath = path
	return p, nil
}

func loadExplicit(format, path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	p, err := loadFormat(format, data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Format = format
	p.FilePath = path
	return p, nil
}

// DetectFormat sniffs SBOM bytes and returns one of the Format* constants.
//
// Heuristics (in order):
//   - leading '<' (after optional BOM / xml prolog) → CycloneDX XML
//   - leading '{' or '[' → JSON; distinguished by "spdxVersion" (SPDX) vs
//     "bomFormat"/"specVersion" (CycloneDX)
//   - presence of "SPDXVersion:" / "PackageName:" lines → SPDX tag-value
func DetectFormat(data []byte) string {
	b := firstNonSpace(data)
	switch b {
	case '<':
		return FormatCycloneDXXML
	case '{', '[':
		// JSON: decide SPDX vs CycloneDX by key presence. Use a cheap substring
		// probe on the head to avoid decoding huge files twice.
		head := data
		if len(head) > 4096 {
			head = head[:4096]
		}
		hs := string(head)
		if strings.Contains(hs, "\"spdxVersion\"") {
			return FormatSPDXJSON
		}
		if strings.Contains(hs, "\"bomFormat\"") || strings.Contains(hs, "\"specVersion\"") {
			return FormatCycloneDXJSON
		}
		// Fall back to a full scan of the whole document for the markers.
		full := string(data)
		if strings.Contains(full, "\"spdxVersion\"") {
			return FormatSPDXJSON
		}
		if strings.Contains(full, "\"bomFormat\"") || strings.Contains(full, "\"specVersion\"") {
			return FormatCycloneDXJSON
		}
		return FormatUnknown
	case 0:
		return FormatUnknown
	default:
		// Likely tag-value text. Confirm by looking for an SPDX tag.
		probe := data
		if len(probe) > 8192 {
			probe = probe[:8192]
		}
		ps := string(probe)
		if strings.Contains(ps, "SPDXVersion:") || strings.Contains(ps, "PackageName:") ||
			strings.Contains(ps, "SPDXID:") || strings.Contains(ps, "DocumentName:") {
			return FormatSPDXTagValue
		}
		return FormatUnknown
	}
}

// firstNonSpace returns the first non-whitespace byte, skipping a UTF-8 BOM and
// an optional XML prolog whitespace. Returns 0 if the input is empty/space-only.
func firstNonSpace(data []byte) byte {
	// Skip UTF-8 BOM.
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	for _, c := range data {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return c
		}
	}
	return 0
}

// Normalize converts a raw SPDX Document into a Parsed view. Callers that use
// Load get Format set for them; when Normalize is called directly the format
// defaults to SPDX JSON (the only serialization that decodes into Document via
// JSON).
func Normalize(doc *Document) *Parsed {
	p := &Parsed{
		Raw:            doc,
		Format:         FormatSPDXJSON,
		Relationships:  doc.Relationships,
		DocAnnotations: doc.Annotations,
		BySPDXID:       make(map[string]*NormalizedPackage, len(doc.Packages)),
	}
	p.ToolLabel, p.ToolName = toolLabel(doc.CreationInfo.Creators)

	// First pass: normalize package fields.
	for i := range doc.Packages {
		np := normalizePackage(&doc.Packages[i])
		p.Packages = append(p.Packages, np)
	}
	// Index by SPDXID (pointer into slice; slice is now stable).
	for i := range p.Packages {
		p.BySPDXID[p.Packages[i].SPDXID] = &p.Packages[i]
	}

	// Second pass: apply graph-derived scope (TEST_DEPENDENCY_OF) and main-module
	// detection from DESCRIBES/documentDescribes.
	applyScopeFromGraph(p, doc)
	applyMainModule(p, doc)

	p.Context = detectContext(doc, p)
	return p
}

// toolLabel returns a human label ("syft v1.42.3") and a short name ("syft")
// from the SPDX creators list. Tool creators look like "Tool: <name>-<version>"
// or "Tool: <name> <version>".
func toolLabel(creators []string) (label, name string) {
	for _, c := range creators {
		c = strings.TrimSpace(c)
		if !strings.HasPrefix(c, "Tool:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(c, "Tool:"))
		// Drop any trailing " source: ..." provenance appended by some tools.
		if idx := strings.Index(rest, " source:"); idx >= 0 {
			rest = strings.TrimSpace(rest[:idx])
		}
		if rest == "" {
			continue
		}
		n, v := splitToolVersion(rest)
		if v != "" {
			return n + " v" + strings.TrimPrefix(v, "v"), n
		}
		return n, n
	}
	// Fall back to first creator or a generic label.
	if len(creators) > 0 {
		return creators[0], creators[0]
	}
	return "unknown-tool", "unknown"
}

// splitToolVersion splits "syft-1.42.3", "syft 1.42.3" or "mikebom-0.1.0-alpha.47"
// into name and version. The version is taken as the substring starting at the
// first digit-leading token after a '-' or space.
func splitToolVersion(s string) (name, version string) {
	// Prefer a space separator if present ("Tool: name version").
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	// Otherwise split on the first '-' that is followed by a digit.
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '-' && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

func normalizePackage(pkg *Package) NormalizedPackage {
	np := NormalizedPackage{
		SPDXID:           pkg.SPDXID,
		Name:             pkg.Name,
		Version:          pkg.VersionInfo,
		LicenseDeclared:  pkg.LicenseDeclared,
		LicenseConcluded: pkg.LicenseConcluded,
		Supplier:         pkg.Supplier,
		Annotations:      pkg.Annotations,
	}

	// Identity from external refs.
	for _, ref := range pkg.ExternalRefs {
		switch ref.ReferenceType {
		case "purl":
			if np.PURL == "" {
				np.PURL = ref.ReferenceLocator
			}
		case "cpe23Type", "cpe23", "cpe":
			if ref.ReferenceLocator != "" {
				np.CPEs = append(np.CPEs, ref.ReferenceLocator)
			}
		}
	}
	np.PURLType, np.ModulePath = parsePURL(np.PURL, np.Name)

	// Checksums.
	np.ChecksumNum = len(pkg.Checksums)
	for _, c := range pkg.Checksums {
		if strings.EqualFold(c.Algorithm, "SHA256") && c.ChecksumValue != "" {
			np.HasSHA256 = true
		}
	}

	// Scope from package-level lifecycle annotations (e.g. mikebom).
	if hasTestLifecycleAnnotation(pkg.Annotations) {
		np.IsTestScoped = true
	}

	// Stdlib heuristic.
	if isStdlib(np.Name, np.PURL) {
		np.IsStdlib = true
	}
	return np
}

// parsePURL extracts the purl type and a best-effort module path. For
// pkg:golang/<module>@<v> the module path is the namespace+name. For
// pkg:generic/<name>@<v> there is no module path, so we fall back to the package
// name to allow cross-type matching of the main module.
func parsePURL(purl, fallbackName string) (purlType, modulePath string) {
	if purl == "" {
		return "", strings.ToLower(fallbackName)
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	// type is up to the first '/'.
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		// e.g. "pkg:golang" with no path — unusual.
		return strings.SplitN(rest, "@", 2)[0], strings.ToLower(fallbackName)
	}
	purlType = rest[:slash]
	pathAndVer := rest[slash+1:]
	// Strip version (@...) and qualifiers (?...) and subpath (#...).
	if i := strings.IndexAny(pathAndVer, "@?#"); i >= 0 {
		pathAndVer = pathAndVer[:i]
	}
	modulePath = strings.ToLower(pathAndVer)
	if modulePath == "" {
		modulePath = strings.ToLower(fallbackName)
	}
	return purlType, modulePath
}

// PURLVersion extracts the @version portion of a purl, if present.
func PURLVersion(purl string) string {
	at := strings.LastIndexByte(purl, '@')
	if at < 0 {
		return ""
	}
	v := purl[at+1:]
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	return v
}

// PURLHasQualifiers reports whether the purl carries ?key=value qualifiers.
func PURLHasQualifiers(purl string) bool {
	return strings.Contains(purl, "?")
}

func hasTestLifecycleAnnotation(anns []Annotation) bool {
	for _, a := range anns {
		c := a.Comment
		if !strings.Contains(c, "lifecycle-scope") {
			continue
		}
		var payload AnnotationPayload
		if json.Unmarshal([]byte(c), &payload) == nil {
			var v string
			if json.Unmarshal(payload.Value, &v) == nil && strings.EqualFold(v, "test") {
				return true
			}
		}
		// Fallback to substring match if not structured.
		if strings.Contains(c, "\"test\"") || strings.Contains(c, ":test") {
			return true
		}
	}
	return false
}

func isStdlib(name, purl string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "stdlib" || n == "go-stdlib" {
		return true
	}
	return strings.Contains(strings.ToLower(purl), "pkg:golang/std")
}

// applyScopeFromGraph marks packages as test-scoped when they are the SUBJECT of
// a TEST_DEPENDENCY_OF relationship (i.e. "X is a test dependency of Y" marks X,
// not Y). Marking the target Y would incorrectly flag the main module as test.
func applyScopeFromGraph(p *Parsed, doc *Document) {
	for _, r := range doc.Relationships {
		if !strings.EqualFold(r.RelationshipType, "TEST_DEPENDENCY_OF") {
			continue
		}
		if np := p.BySPDXID[r.SPDXElementID]; np != nil {
			np.IsTestScoped = true
		}
	}
}

// applyMainModule flags the package(s) the document DESCRIBES. SPDX wraps the
// described element in a DocumentRoot, so we resolve one hop: DOCUMENT
// -DESCRIBES-> Root, and treat the package the Root DESCRIBES/CONTAINS as main.
// We also directly flag any package the DOCUMENT DESCRIBES.
func applyMainModule(p *Parsed, doc *Document) {
	described := map[string]bool{}
	roots := map[string]bool{}
	for _, r := range doc.Relationships {
		if strings.EqualFold(r.RelationshipType, "DESCRIBES") {
			roots[r.RelatedSPDXElement] = true
			if np := p.BySPDXID[r.RelatedSPDXElement]; np != nil {
				described[np.SPDXID] = true
			}
		}
	}
	// One hop from roots via DESCRIBES/CONTAINS to find the real main package.
	for _, r := range doc.Relationships {
		if !roots[r.SPDXElementID] {
			continue
		}
		if strings.EqualFold(r.RelationshipType, "DESCRIBES") ||
			strings.EqualFold(r.RelationshipType, "CONTAINS") ||
			strings.EqualFold(r.RelationshipType, "GENERATED_FROM") {
			if np := p.BySPDXID[r.RelatedSPDXElement]; np != nil {
				described[np.SPDXID] = true
			}
		}
	}
	for _, id := range doc.DocumentDescribes {
		if np := p.BySPDXID[id]; np != nil {
			described[np.SPDXID] = true
		}
	}
	for id := range described {
		if np := p.BySPDXID[id]; np != nil {
			np.IsMainModule = true
		}
	}
}

// detectContext infers whether the SBOM describes source or a built binary,
// using creators provenance, sourceInfo and annotations as signals.
func detectContext(doc *Document, p *Parsed) string {
	joined := strings.ToLower(strings.Join(doc.CreationInfo.Creators, " "))
	// Tool provenance hints.
	if strings.Contains(joined, "go.sum") || strings.Contains(joined, "repo:") ||
		strings.Contains(joined, "git:") || strings.Contains(joined, "filesystem") {
		return "source"
	}
	// Document/package annotations (e.g. mikebom:sbom-tier=source, source-files).
	tierSource, tierBinary := scanTierAnnotations(p)
	if tierSource && !tierBinary {
		return "source"
	}
	if tierBinary && !tierSource {
		return "binary"
	}
	// Binary signals: a stdlib component or sourceInfo referencing a binary.
	for i := range p.Packages {
		if p.Packages[i].IsStdlib {
			return "binary"
		}
	}
	for _, pkg := range doc.Packages {
		si := strings.ToLower(pkg.SourceInfo)
		if strings.Contains(si, "binary") || strings.Contains(si, ".tar.gz") ||
			strings.Contains(si, "acquired package info from") {
			return "binary"
		}
	}
	return "unknown"
}

func scanTierAnnotations(p *Parsed) (source, binary bool) {
	check := func(anns []Annotation) {
		for _, a := range anns {
			c := strings.ToLower(a.Comment)
			if !strings.Contains(c, "sbom-tier") && !strings.Contains(c, "source-files") {
				continue
			}
			if strings.Contains(c, "source-files") || strings.Contains(c, "\"source\"") {
				source = true
			}
			if strings.Contains(c, "\"binary\"") {
				binary = true
			}
		}
	}
	check(p.DocAnnotations)
	for i := range p.Packages {
		check(p.Packages[i].Annotations)
	}
	return source, binary
}

// SortedPackages returns packages sorted by name then version for deterministic
// output.
func (p *Parsed) SortedPackages() []NormalizedPackage {
	out := make([]NormalizedPackage, len(p.Packages))
	copy(out, p.Packages)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}
